// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package api

import (
	context "context"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// AppIdentityServiceClient is the client API for AppIdentityService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AppIdentityServiceClient interface {
	// Create an application.
	CreateApp(ctx context.Context, in *CreateAppRequest, opts ...grpc.CallOption) (*App, error)
	// Create an identity.
	CreateIdentity(ctx context.Context, in *CreateIdentityRequest, opts ...grpc.CallOption) (*CreateIdentityResponse, error)
	// Activate an identity.
	ActivateIdentity(ctx context.Context, in *ActivateIdentityRequest, opts ...grpc.CallOption) (*Identity, error)
	// Issue a challenge to an identity.
	ChallengeIdentity(ctx context.Context, in *ChallengeIdentityRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	// Verify an identity.
	VerifyIdentity(ctx context.Context, in *VerifyIdentityRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	// Get an application by ID.
	GetApp(ctx context.Context, in *GetAppRequest, opts ...grpc.CallOption) (*App, error)
	// Get an identity by ID.
	GetIdentity(ctx context.Context, in *GetIdentityRequest, opts ...grpc.CallOption) (*Identity, error)
	// Update an application.
	UpdateApp(ctx context.Context, in *UpdateAppRequest, opts ...grpc.CallOption) (*App, error)
	// Delete an application by ID.
	DeleteApp(ctx context.Context, in *DeleteAppRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	// Delete an identity by ID.
	DeleteIdentity(ctx context.Context, in *DeleteIdentityRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	// List all applications.
	ListApps(ctx context.Context, in *ListAppsRequest, opts ...grpc.CallOption) (*ListAppsResponse, error)
	// List identities.
	ListIdentities(ctx context.Context, in *ListIdentitiesRequest, opts ...grpc.CallOption) (*ListIdentitiesResponse, error)
}

type appIdentityServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAppIdentityServiceClient(cc grpc.ClientConnInterface) AppIdentityServiceClient {
	return &appIdentityServiceClient{cc}
}

func (c *appIdentityServiceClient) CreateApp(ctx context.Context, in *CreateAppRequest, opts ...grpc.CallOption) (*App, error) {
	out := new(App)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/CreateApp", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) CreateIdentity(ctx context.Context, in *CreateIdentityRequest, opts ...grpc.CallOption) (*CreateIdentityResponse, error) {
	out := new(CreateIdentityResponse)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/CreateIdentity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) ActivateIdentity(ctx context.Context, in *ActivateIdentityRequest, opts ...grpc.CallOption) (*Identity, error) {
	out := new(Identity)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/ActivateIdentity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) ChallengeIdentity(ctx context.Context, in *ChallengeIdentityRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/ChallengeIdentity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) VerifyIdentity(ctx context.Context, in *VerifyIdentityRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/VerifyIdentity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) GetApp(ctx context.Context, in *GetAppRequest, opts ...grpc.CallOption) (*App, error) {
	out := new(App)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/GetApp", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) GetIdentity(ctx context.Context, in *GetIdentityRequest, opts ...grpc.CallOption) (*Identity, error) {
	out := new(Identity)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/GetIdentity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) UpdateApp(ctx context.Context, in *UpdateAppRequest, opts ...grpc.CallOption) (*App, error) {
	out := new(App)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/UpdateApp", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) DeleteApp(ctx context.Context, in *DeleteAppRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/DeleteApp", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) DeleteIdentity(ctx context.Context, in *DeleteIdentityRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/DeleteIdentity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) ListApps(ctx context.Context, in *ListAppsRequest, opts ...grpc.CallOption) (*ListAppsResponse, error) {
	out := new(ListAppsResponse)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/ListApps", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appIdentityServiceClient) ListIdentities(ctx context.Context, in *ListIdentitiesRequest, opts ...grpc.CallOption) (*ListIdentitiesResponse, error) {
	out := new(ListIdentitiesResponse)
	err := c.cc.Invoke(ctx, "/ownmfa.api.AppIdentityService/ListIdentities", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AppIdentityServiceServer is the server API for AppIdentityService service.
// All implementations must embed UnimplementedAppIdentityServiceServer
// for forward compatibility
type AppIdentityServiceServer interface {
	// Create an application.
	CreateApp(context.Context, *CreateAppRequest) (*App, error)
	// Create an identity.
	CreateIdentity(context.Context, *CreateIdentityRequest) (*CreateIdentityResponse, error)
	// Activate an identity.
	ActivateIdentity(context.Context, *ActivateIdentityRequest) (*Identity, error)
	// Issue a challenge to an identity.
	ChallengeIdentity(context.Context, *ChallengeIdentityRequest) (*empty.Empty, error)
	// Verify an identity.
	VerifyIdentity(context.Context, *VerifyIdentityRequest) (*empty.Empty, error)
	// Get an application by ID.
	GetApp(context.Context, *GetAppRequest) (*App, error)
	// Get an identity by ID.
	GetIdentity(context.Context, *GetIdentityRequest) (*Identity, error)
	// Update an application.
	UpdateApp(context.Context, *UpdateAppRequest) (*App, error)
	// Delete an application by ID.
	DeleteApp(context.Context, *DeleteAppRequest) (*empty.Empty, error)
	// Delete an identity by ID.
	DeleteIdentity(context.Context, *DeleteIdentityRequest) (*empty.Empty, error)
	// List all applications.
	ListApps(context.Context, *ListAppsRequest) (*ListAppsResponse, error)
	// List identities.
	ListIdentities(context.Context, *ListIdentitiesRequest) (*ListIdentitiesResponse, error)
	mustEmbedUnimplementedAppIdentityServiceServer()
}

// UnimplementedAppIdentityServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAppIdentityServiceServer struct {
}

func (UnimplementedAppIdentityServiceServer) CreateApp(context.Context, *CreateAppRequest) (*App, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateApp not implemented")
}
func (UnimplementedAppIdentityServiceServer) CreateIdentity(context.Context, *CreateIdentityRequest) (*CreateIdentityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateIdentity not implemented")
}
func (UnimplementedAppIdentityServiceServer) ActivateIdentity(context.Context, *ActivateIdentityRequest) (*Identity, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivateIdentity not implemented")
}
func (UnimplementedAppIdentityServiceServer) ChallengeIdentity(context.Context, *ChallengeIdentityRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChallengeIdentity not implemented")
}
func (UnimplementedAppIdentityServiceServer) VerifyIdentity(context.Context, *VerifyIdentityRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyIdentity not implemented")
}
func (UnimplementedAppIdentityServiceServer) GetApp(context.Context, *GetAppRequest) (*App, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetApp not implemented")
}
func (UnimplementedAppIdentityServiceServer) GetIdentity(context.Context, *GetIdentityRequest) (*Identity, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetIdentity not implemented")
}
func (UnimplementedAppIdentityServiceServer) UpdateApp(context.Context, *UpdateAppRequest) (*App, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateApp not implemented")
}
func (UnimplementedAppIdentityServiceServer) DeleteApp(context.Context, *DeleteAppRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteApp not implemented")
}
func (UnimplementedAppIdentityServiceServer) DeleteIdentity(context.Context, *DeleteIdentityRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteIdentity not implemented")
}
func (UnimplementedAppIdentityServiceServer) ListApps(context.Context, *ListAppsRequest) (*ListAppsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListApps not implemented")
}
func (UnimplementedAppIdentityServiceServer) ListIdentities(context.Context, *ListIdentitiesRequest) (*ListIdentitiesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListIdentities not implemented")
}
func (UnimplementedAppIdentityServiceServer) mustEmbedUnimplementedAppIdentityServiceServer() {}

// UnsafeAppIdentityServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AppIdentityServiceServer will
// result in compilation errors.
type UnsafeAppIdentityServiceServer interface {
	mustEmbedUnimplementedAppIdentityServiceServer()
}

func RegisterAppIdentityServiceServer(s grpc.ServiceRegistrar, srv AppIdentityServiceServer) {
	s.RegisterService(&AppIdentityService_ServiceDesc, srv)
}

func _AppIdentityService_CreateApp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAppRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).CreateApp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/CreateApp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).CreateApp(ctx, req.(*CreateAppRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_CreateIdentity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateIdentityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).CreateIdentity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/CreateIdentity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).CreateIdentity(ctx, req.(*CreateIdentityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_ActivateIdentity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivateIdentityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).ActivateIdentity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/ActivateIdentity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).ActivateIdentity(ctx, req.(*ActivateIdentityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_ChallengeIdentity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChallengeIdentityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).ChallengeIdentity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/ChallengeIdentity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).ChallengeIdentity(ctx, req.(*ChallengeIdentityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_VerifyIdentity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyIdentityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).VerifyIdentity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/VerifyIdentity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).VerifyIdentity(ctx, req.(*VerifyIdentityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_GetApp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAppRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).GetApp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/GetApp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).GetApp(ctx, req.(*GetAppRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_GetIdentity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetIdentityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).GetIdentity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/GetIdentity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).GetIdentity(ctx, req.(*GetIdentityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_UpdateApp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAppRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).UpdateApp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/UpdateApp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).UpdateApp(ctx, req.(*UpdateAppRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_DeleteApp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAppRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).DeleteApp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/DeleteApp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).DeleteApp(ctx, req.(*DeleteAppRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_DeleteIdentity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteIdentityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).DeleteIdentity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/DeleteIdentity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).DeleteIdentity(ctx, req.(*DeleteIdentityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_ListApps_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAppsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).ListApps(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/ListApps",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).ListApps(ctx, req.(*ListAppsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppIdentityService_ListIdentities_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListIdentitiesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppIdentityServiceServer).ListIdentities(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ownmfa.api.AppIdentityService/ListIdentities",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppIdentityServiceServer).ListIdentities(ctx, req.(*ListIdentitiesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AppIdentityService_ServiceDesc is the grpc.ServiceDesc for AppIdentityService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AppIdentityService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "ownmfa.api.AppIdentityService",
	HandlerType: (*AppIdentityServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateApp",
			Handler:    _AppIdentityService_CreateApp_Handler,
		},
		{
			MethodName: "CreateIdentity",
			Handler:    _AppIdentityService_CreateIdentity_Handler,
		},
		{
			MethodName: "ActivateIdentity",
			Handler:    _AppIdentityService_ActivateIdentity_Handler,
		},
		{
			MethodName: "ChallengeIdentity",
			Handler:    _AppIdentityService_ChallengeIdentity_Handler,
		},
		{
			MethodName: "VerifyIdentity",
			Handler:    _AppIdentityService_VerifyIdentity_Handler,
		},
		{
			MethodName: "GetApp",
			Handler:    _AppIdentityService_GetApp_Handler,
		},
		{
			MethodName: "GetIdentity",
			Handler:    _AppIdentityService_GetIdentity_Handler,
		},
		{
			MethodName: "UpdateApp",
			Handler:    _AppIdentityService_UpdateApp_Handler,
		},
		{
			MethodName: "DeleteApp",
			Handler:    _AppIdentityService_DeleteApp_Handler,
		},
		{
			MethodName: "DeleteIdentity",
			Handler:    _AppIdentityService_DeleteIdentity_Handler,
		},
		{
			MethodName: "ListApps",
			Handler:    _AppIdentityService_ListApps_Handler,
		},
		{
			MethodName: "ListIdentities",
			Handler:    _AppIdentityService_ListIdentities_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/app_identity.proto",
}
