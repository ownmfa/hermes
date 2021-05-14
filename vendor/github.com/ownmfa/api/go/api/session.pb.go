// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.13.0
// source: api/session.proto

package api

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	empty "github.com/golang/protobuf/ptypes/empty"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	common "github.com/ownmfa/api/go/common"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// LoginRequest is sent to log in a user.
type LoginRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Email of the user to log in.
	Email string `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	// Organization name of the user to log in.
	OrgName string `protobuf:"bytes,2,opt,name=org_name,json=orgName,proto3" json:"org_name,omitempty"`
	// Password of the user to log in.
	Password string `protobuf:"bytes,3,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *LoginRequest) Reset() {
	*x = LoginRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoginRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginRequest) ProtoMessage() {}

func (x *LoginRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginRequest.ProtoReflect.Descriptor instead.
func (*LoginRequest) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{0}
}

func (x *LoginRequest) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *LoginRequest) GetOrgName() string {
	if x != nil {
		return x.OrgName
	}
	return ""
}

func (x *LoginRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

// LoginResponse is sent in response to a user login.
type LoginResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Token to be used for subsequent non-login calls.
	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	// Token expiration timestamp.
	ExpiresAt *timestamp.Timestamp `protobuf:"bytes,2,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
}

func (x *LoginResponse) Reset() {
	*x = LoginResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoginResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginResponse) ProtoMessage() {}

func (x *LoginResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginResponse.ProtoReflect.Descriptor instead.
func (*LoginResponse) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{1}
}

func (x *LoginResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *LoginResponse) GetExpiresAt() *timestamp.Timestamp {
	if x != nil {
		return x.ExpiresAt
	}
	return nil
}

// Key represents an API key as stored in the database. API keys are not tied to a specific user.
type Key struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Key ID (UUID).
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Organization ID (UUID).
	OrgId string `protobuf:"bytes,2,opt,name=org_id,json=orgID,proto3" json:"org_id,omitempty"`
	// Key name.
	Name string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	// Key role.
	Role common.Role `protobuf:"varint,4,opt,name=role,proto3,enum=ownmfa.common.Role" json:"role,omitempty"`
	// Key creation timestamp.
	CreatedAt *timestamp.Timestamp `protobuf:"bytes,5,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
}

func (x *Key) Reset() {
	*x = Key{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Key) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Key) ProtoMessage() {}

func (x *Key) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Key.ProtoReflect.Descriptor instead.
func (*Key) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{2}
}

func (x *Key) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Key) GetOrgId() string {
	if x != nil {
		return x.OrgId
	}
	return ""
}

func (x *Key) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Key) GetRole() common.Role {
	if x != nil {
		return x.Role
	}
	return common.Role_ROLE_UNSPECIFIED
}

func (x *Key) GetCreatedAt() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

// CreateKeyRequest is sent to create an API key.
type CreateKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Key message to create.
	Key *Key `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *CreateKeyRequest) Reset() {
	*x = CreateKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateKeyRequest) ProtoMessage() {}

func (x *CreateKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateKeyRequest.ProtoReflect.Descriptor instead.
func (*CreateKeyRequest) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{3}
}

func (x *CreateKeyRequest) GetKey() *Key {
	if x != nil {
		return x.Key
	}
	return nil
}

// CreateKeyResponse is sent in response to an API key creation.
type CreateKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Key message created.
	Key *Key `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// Token to be used for subsequent calls. Only returned once, upon key creation.
	Token string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *CreateKeyResponse) Reset() {
	*x = CreateKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateKeyResponse) ProtoMessage() {}

func (x *CreateKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateKeyResponse.ProtoReflect.Descriptor instead.
func (*CreateKeyResponse) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{4}
}

func (x *CreateKeyResponse) GetKey() *Key {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *CreateKeyResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

// DeleteKeyRequest is sent to delete an API key.
type DeleteKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Key ID (UUID) to delete.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *DeleteKeyRequest) Reset() {
	*x = DeleteKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteKeyRequest) ProtoMessage() {}

func (x *DeleteKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteKeyRequest.ProtoReflect.Descriptor instead.
func (*DeleteKeyRequest) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{5}
}

func (x *DeleteKeyRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// ListKeysRequest is sent to list API keys.
type ListKeysRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Number of API keys to retrieve in a single page. Defaults to 50 if not specified, with a maximum of 250.
	PageSize int32 `protobuf:"varint,1,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// Token of the page to retrieve. If not specified, the first page of results will be returned. To request the next page of results, use next_page_token from the previous response.
	PageToken string `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
}

func (x *ListKeysRequest) Reset() {
	*x = ListKeysRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListKeysRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListKeysRequest) ProtoMessage() {}

func (x *ListKeysRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListKeysRequest.ProtoReflect.Descriptor instead.
func (*ListKeysRequest) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{6}
}

func (x *ListKeysRequest) GetPageSize() int32 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListKeysRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

// ListKeysResponse is sent in response to an API key list.
type ListKeysResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Key array, ordered by ascending created_at timestamp.
	Keys []*Key `protobuf:"bytes,1,rep,name=keys,proto3" json:"keys,omitempty"`
	// Pagination token used to retrieve the next page of results. Not returned for the last page.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
	// Total number of API keys available.
	TotalSize int32 `protobuf:"varint,3,opt,name=total_size,json=totalSize,proto3" json:"total_size,omitempty"`
}

func (x *ListKeysResponse) Reset() {
	*x = ListKeysResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_session_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListKeysResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListKeysResponse) ProtoMessage() {}

func (x *ListKeysResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_session_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListKeysResponse.ProtoReflect.Descriptor instead.
func (*ListKeysResponse) Descriptor() ([]byte, []int) {
	return file_api_session_proto_rawDescGZIP(), []int{7}
}

func (x *ListKeysResponse) GetKeys() []*Key {
	if x != nil {
		return x.Keys
	}
	return nil
}

func (x *ListKeysResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

func (x *ListKeysResponse) GetTotalSize() int32 {
	if x != nil {
		return x.TotalSize
	}
	return 0
}

var File_api_session_proto protoreflect.FileDescriptor

var file_api_session_proto_rawDesc = []byte{
	0x0a, 0x11, 0x61, 0x70, 0x69, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x1a,
	0x11, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x72, 0x6f, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64,
	0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e,
	0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x6a, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x69,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69,
	0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x05, 0x65, 0x6d,
	0x61, 0x69, 0x6c, 0x12, 0x1e, 0x0a, 0x08, 0x6f, 0x72, 0x67, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x07, 0x6f, 0x72, 0x67, 0x4e,
	0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x22, 0x60, 0x0a, 0x0d, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x39, 0x0a, 0x0a, 0x65,
	0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x65, 0x78, 0x70,
	0x69, 0x72, 0x65, 0x73, 0x41, 0x74, 0x22, 0xd4, 0x01, 0x0a, 0x03, 0x4b, 0x65, 0x79, 0x12, 0x13,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52,
	0x02, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49, 0x44, 0x12,
	0x20, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0c, 0xfa,
	0x42, 0x06, 0x72, 0x04, 0x10, 0x05, 0x18, 0x50, 0xe0, 0x41, 0x02, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x3a, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x13, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x52, 0x6f, 0x6c, 0x65, 0x42, 0x11, 0xfa, 0x42, 0x0b, 0x82, 0x01, 0x08, 0x18, 0x04, 0x18, 0x08,
	0x18, 0x0c, 0x18, 0x0f, 0xe0, 0x41, 0x02, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x3e, 0x0a,
	0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0,
	0x41, 0x03, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0x42, 0x0a,
	0x10, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x2e, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f,
	0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4b, 0x65, 0x79, 0x42,
	0x0b, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0xe0, 0x41, 0x02, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x22, 0x4c, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x21, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x4b, 0x65, 0x79, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22,
	0x2f, 0x0a, 0x10, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42,
	0x0b, 0xfa, 0x42, 0x05, 0x72, 0x03, 0xb0, 0x01, 0x01, 0xe0, 0x41, 0x02, 0x52, 0x02, 0x69, 0x64,
	0x22, 0x57, 0x0a, 0x0f, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x25, 0x0a, 0x09, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x1a, 0x03, 0x18, 0xfa, 0x01,
	0x52, 0x08, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61,
	0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x70, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x7e, 0x0a, 0x10, 0x4c, 0x69, 0x73,
	0x74, 0x4b, 0x65, 0x79, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x23, 0x0a,
	0x04, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6f, 0x77,
	0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4b, 0x65, 0x79, 0x52, 0x04, 0x6b, 0x65,
	0x79, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x5f,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x6e, 0x65, 0x78,
	0x74, 0x50, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x6f,
	0x74, 0x61, 0x6c, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09,
	0x74, 0x6f, 0x74, 0x61, 0x6c, 0x53, 0x69, 0x7a, 0x65, 0x32, 0x82, 0x04, 0x0a, 0x0e, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x60, 0x0a, 0x05,
	0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x12, 0x18, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x19, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4c, 0x6f, 0x67,
	0x69, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x22, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x17, 0x22, 0x12, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x3a, 0x01, 0x2a, 0x92, 0x41, 0x02, 0x62, 0x00, 0x12, 0xa1,
	0x01, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x1c, 0x2e, 0x6f,
	0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1d, 0x2e, 0x6f, 0x77, 0x6e,
	0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x57, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x18, 0x22, 0x11, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x6b, 0x65, 0x79, 0x73, 0x3a, 0x03, 0x6b, 0x65, 0x79, 0x92, 0x41, 0x36, 0x4a, 0x34, 0x0a, 0x03,
	0x32, 0x30, 0x31, 0x12, 0x2d, 0x0a, 0x16, 0x41, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x66, 0x75, 0x6c, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x12, 0x13, 0x0a,
	0x11, 0x1a, 0x0f, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4b,
	0x65, 0x79, 0x12, 0x87, 0x01, 0x0a, 0x09, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65, 0x79,
	0x12, 0x1c, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x44, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x18, 0x2a, 0x16,
	0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x6b, 0x65, 0x79,
	0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x92, 0x41, 0x23, 0x4a, 0x21, 0x0a, 0x03, 0x32, 0x30, 0x34,
	0x12, 0x1a, 0x0a, 0x16, 0x41, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x66, 0x75, 0x6c,
	0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x12, 0x00, 0x12, 0x60, 0x0a, 0x08,
	0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x12, 0x1b, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66,
	0x61, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x19, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x13, 0x12, 0x11, 0x2f, 0x76, 0x31,
	0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x6b, 0x65, 0x79, 0x73, 0x42, 0x1e,
	0x5a, 0x1c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x77, 0x6e,
	0x6d, 0x66, 0x61, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x6f, 0x2f, 0x61, 0x70, 0x69, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_session_proto_rawDescOnce sync.Once
	file_api_session_proto_rawDescData = file_api_session_proto_rawDesc
)

func file_api_session_proto_rawDescGZIP() []byte {
	file_api_session_proto_rawDescOnce.Do(func() {
		file_api_session_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_session_proto_rawDescData)
	})
	return file_api_session_proto_rawDescData
}

var file_api_session_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_api_session_proto_goTypes = []interface{}{
	(*LoginRequest)(nil),        // 0: ownmfa.api.LoginRequest
	(*LoginResponse)(nil),       // 1: ownmfa.api.LoginResponse
	(*Key)(nil),                 // 2: ownmfa.api.Key
	(*CreateKeyRequest)(nil),    // 3: ownmfa.api.CreateKeyRequest
	(*CreateKeyResponse)(nil),   // 4: ownmfa.api.CreateKeyResponse
	(*DeleteKeyRequest)(nil),    // 5: ownmfa.api.DeleteKeyRequest
	(*ListKeysRequest)(nil),     // 6: ownmfa.api.ListKeysRequest
	(*ListKeysResponse)(nil),    // 7: ownmfa.api.ListKeysResponse
	(*timestamp.Timestamp)(nil), // 8: google.protobuf.Timestamp
	(common.Role)(0),            // 9: ownmfa.common.Role
	(*empty.Empty)(nil),         // 10: google.protobuf.Empty
}
var file_api_session_proto_depIdxs = []int32{
	8,  // 0: ownmfa.api.LoginResponse.expires_at:type_name -> google.protobuf.Timestamp
	9,  // 1: ownmfa.api.Key.role:type_name -> ownmfa.common.Role
	8,  // 2: ownmfa.api.Key.created_at:type_name -> google.protobuf.Timestamp
	2,  // 3: ownmfa.api.CreateKeyRequest.key:type_name -> ownmfa.api.Key
	2,  // 4: ownmfa.api.CreateKeyResponse.key:type_name -> ownmfa.api.Key
	2,  // 5: ownmfa.api.ListKeysResponse.keys:type_name -> ownmfa.api.Key
	0,  // 6: ownmfa.api.SessionService.Login:input_type -> ownmfa.api.LoginRequest
	3,  // 7: ownmfa.api.SessionService.CreateKey:input_type -> ownmfa.api.CreateKeyRequest
	5,  // 8: ownmfa.api.SessionService.DeleteKey:input_type -> ownmfa.api.DeleteKeyRequest
	6,  // 9: ownmfa.api.SessionService.ListKeys:input_type -> ownmfa.api.ListKeysRequest
	1,  // 10: ownmfa.api.SessionService.Login:output_type -> ownmfa.api.LoginResponse
	4,  // 11: ownmfa.api.SessionService.CreateKey:output_type -> ownmfa.api.CreateKeyResponse
	10, // 12: ownmfa.api.SessionService.DeleteKey:output_type -> google.protobuf.Empty
	7,  // 13: ownmfa.api.SessionService.ListKeys:output_type -> ownmfa.api.ListKeysResponse
	10, // [10:14] is the sub-list for method output_type
	6,  // [6:10] is the sub-list for method input_type
	6,  // [6:6] is the sub-list for extension type_name
	6,  // [6:6] is the sub-list for extension extendee
	0,  // [0:6] is the sub-list for field type_name
}

func init() { file_api_session_proto_init() }
func file_api_session_proto_init() {
	if File_api_session_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_session_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoginRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_session_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoginResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_session_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Key); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_session_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_session_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_session_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_session_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListKeysRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_session_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListKeysResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_session_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_session_proto_goTypes,
		DependencyIndexes: file_api_session_proto_depIdxs,
		MessageInfos:      file_api_session_proto_msgTypes,
	}.Build()
	File_api_session_proto = out.File
	file_api_session_proto_rawDesc = nil
	file_api_session_proto_goTypes = nil
	file_api_session_proto_depIdxs = nil
}
