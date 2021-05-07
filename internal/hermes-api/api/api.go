// Package api provides functions used to run the API service.
package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/NYTimes/gziphandler"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/internal/hermes-api/config"
	"github.com/ownmfa/hermes/internal/hermes-api/interceptor"
	"github.com/ownmfa/hermes/internal/hermes-api/service"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/dao/app"
	"github.com/ownmfa/hermes/pkg/dao/identity"
	"github.com/ownmfa/hermes/pkg/dao/key"
	"github.com/ownmfa/hermes/pkg/dao/org"
	"github.com/ownmfa/hermes/pkg/dao/user"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/queue"
	"google.golang.org/grpc"

	// encoding/gzip imported for use by UseCompressor CallOption.
	_ "google.golang.org/grpc/encoding/gzip"
)

const (
	ServiceName = "api"
	GRPCHost    = "127.0.0.1"
	GRPCPort    = ":50051"
	httpPort    = ":8000"

	errPWTLength      consterr.Error = "pwt key must be 32 bytes"
	errIdentityLength consterr.Error = "identity key must be 32 bytes"
)

// API holds references to the gRPC and HTTP servers.
type API struct {
	grpcSrv    *grpc.Server
	httpSrv    *http.Server
	httpCancel context.CancelFunc
}

// New builds a new API and returns a reference to it and an error value.
func New(cfg *config.Config) (*API, error) {
	// Validate Config.
	if len(cfg.PWTKey) != 32 {
		return nil, errPWTLength
	}

	if len(cfg.IdentityKey) != 32 {
		return nil, errIdentityLength
	}

	// Set up database connection.
	pg, err := dao.NewPgDB(cfg.PgURI)
	if err != nil {
		return nil, err
	}

	// Set up cache connection.
	redis, err := cache.NewRedis(cfg.RedisHost + ":6379")
	if err != nil {
		return nil, err
	}

	// Set up Notifier. Allow a mock for local usage, but warn loudly.
	var n notify.Notifier
	if cfg.SMSSecret == "" {
		hlog.Error("New notify secrets not found, using notify.NewFake()")
		n = notify.NewFake()
	} else {
		n = notify.New(redis, "", cfg.SMSSID, cfg.SMSSecret, "", "")
	}

	// Build the NSQ connection for publishing.
	nsq, err := queue.NewNSQ(cfg.NSQPubAddr, nil, "",
		queue.DefaultNSQRequeueDelay)
	if err != nil {
		return nil, err
	}

	// Register gRPC services.
	skipAuth := map[string]struct{}{
		"/ownmfa.api.SessionService/Login": {},
	}
	skipValidate := map[string]struct{}{
		// Update actions validate after merge to support partial updates.
		"/ownmfa.api.AppIdentityService/UpdateApp": {},
		"/ownmfa.api.OrgService/UpdateOrg":         {},
		"/ownmfa.api.UserService/UpdateUser":       {},
	}

	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(
		interceptor.Log(nil),
		interceptor.Auth(skipAuth, cfg.PWTKey, redis),
		interceptor.Validate(skipValidate),
	))
	api.RegisterAppIdentityServiceServer(srv,
		service.NewAppIdentity(app.NewDAO(pg), identity.NewDAO(pg,
			cfg.IdentityKey), redis, n, nsq, cfg.NSQPubTopic))
	api.RegisterOrgServiceServer(srv, service.NewOrg(org.NewDAO(pg)))
	api.RegisterSessionServiceServer(srv, service.NewSession(user.NewDAO(pg),
		key.NewDAO(pg), redis, cfg.PWTKey))
	api.RegisterUserServiceServer(srv, service.NewUser(user.NewDAO(pg)))

	// Register gRPC-Gateway handlers.
	ctx, cancel := context.WithCancel(context.Background())
	gwMux := runtime.NewServeMux(runtime.WithForwardResponseOption(statusCode))
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
	}

	// App and Identity.
	if err := api.RegisterAppIdentityServiceHandlerFromEndpoint(ctx, gwMux,
		GRPCHost+GRPCPort, opts); err != nil {
		cancel()

		return nil, err
	}

	// Org.
	if err := api.RegisterOrgServiceHandlerFromEndpoint(ctx, gwMux,
		GRPCHost+GRPCPort, opts); err != nil {
		cancel()

		return nil, err
	}

	// Session.
	if err := api.RegisterSessionServiceHandlerFromEndpoint(ctx, gwMux,
		GRPCHost+GRPCPort, opts); err != nil {
		cancel()

		return nil, err
	}

	// User.
	if err := api.RegisterUserServiceHandlerFromEndpoint(ctx, gwMux,
		GRPCHost+GRPCPort, opts); err != nil {
		cancel()

		return nil, err
	}

	// OpenAPI.
	mux := http.NewServeMux()
	mux.Handle("/v1/", gwMux)
	mux.Handle("/", http.FileServer(http.Dir("web")))

	return &API{
		grpcSrv: srv,
		httpSrv: &http.Server{
			Addr:    httpPort,
			Handler: gziphandler.GzipHandler(mux),
		},
		httpCancel: cancel,
	}, nil
}

// Serve starts the listener.
func (api *API) Serve() {
	//#nosec G102 // service should listen on all interfaces
	lis, err := net.Listen("tcp", GRPCPort)
	if err != nil {
		hlog.Fatalf("Serve net.Listen: %v", err)
	}

	// Serve gRPC.
	go func() {
		hlog.Infof("Listening on %v", GRPCPort)
		if err := api.grpcSrv.Serve(lis); err != nil {
			hlog.Fatalf("Serve api.grpcSrv.Serve: %v", err)
		}
	}()

	// Serve gRPC-gateway.
	go func() {
		hlog.Infof("Listening on %v", httpPort)
		if err := api.httpSrv.ListenAndServe(); err != nil {
			hlog.Fatalf("Serve api.httpSrv.ListenAndServe: %v", err)
		}
	}()

	// Handle graceful shutdown.
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, syscall.SIGINT, syscall.SIGTERM)
	<-exitChan

	hlog.Info("Serve received signal, exiting")
	api.httpCancel()
}
