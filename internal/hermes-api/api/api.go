// Package api provides functions used to run the API service.
package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	"github.com/ownmfa/hermes/pkg/dao/event"
	"github.com/ownmfa/hermes/pkg/dao/identity"
	"github.com/ownmfa/hermes/pkg/dao/key"
	"github.com/ownmfa/hermes/pkg/dao/org"
	"github.com/ownmfa/hermes/pkg/dao/user"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/queue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip" // For UseCompressor CallOption.
)

// ServiceName provides consistent naming, including logs and metrics.
const ServiceName = "api"

// Constants used for service configuration.
const (
	GRPCHost = "127.0.0.1"
	GRPCPort = ":50051"
	httpPort = ":8000"
	orgExp   = 15 * time.Minute
)

// Errors returned due to insufficient key length.
const (
	//#nosec G101 // false positive for hardcoded credentials
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
	if cfg.SMSKeySecret == "" || cfg.PushoverAPIKey == "" {
		hlog.Error("New notify secrets not found, using notify.NewFake()")
		n = notify.NewFake()
	} else {
		n = notify.New(redis, cfg.SMSKeyID, "", cfg.SMSKeySecret, "",
			cfg.PushoverAPIKey, "", "")
	}

	// Build the NSQ connection for publishing.
	nsq, err := queue.NewNSQ(cfg.NSQPubAddr, nil, "")
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

	orgDAO := org.NewDAO(pg, redis, orgExp)
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(
		interceptor.Log(nil),
		interceptor.Auth(skipAuth, cfg.PWTKey, redis, orgDAO),
		interceptor.Validate(skipValidate),
	))

	api.RegisterAppIdentityServiceServer(srv,
		service.NewAppIdentity(app.NewDAO(pg), identity.NewDAO(pg,
			cfg.IdentityKey), event.NewDAO(pg), redis, n, nsq, cfg.NSQPubTopic))
	api.RegisterEventServiceServer(srv, service.NewEvent(event.NewDAO(pg)))
	api.RegisterOrgServiceServer(srv, service.NewOrg(orgDAO))
	api.RegisterSessionServiceServer(srv, service.NewSession(user.NewDAO(pg),
		key.NewDAO(pg), redis, cfg.PWTKey))
	api.RegisterUserServiceServer(srv, service.NewUser(user.NewDAO(pg)))

	// Register gRPC-Gateway handlers.
	ctx, cancel := context.WithCancel(context.Background())
	gwMux := runtime.NewServeMux(runtime.WithForwardResponseOption(statusCode))
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	// App and Identity.
	if err := api.RegisterAppIdentityServiceHandlerFromEndpoint(ctx, gwMux,
		GRPCHost+GRPCPort, opts); err != nil {
		cancel()

		return nil, err
	}

	// Event.
	if err := api.RegisterEventServiceHandlerFromEndpoint(ctx, gwMux,
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
			Addr:              httpPort,
			Handler:           gziphandler.GzipHandler(mux),
			ReadHeaderTimeout: 60 * time.Second,
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
