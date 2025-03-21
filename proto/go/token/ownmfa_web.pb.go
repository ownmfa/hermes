// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v4.24.4
// source: token/ownmfa_web.proto

package token

import (
	api "github.com/ownmfa/proto/go/api"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Web represents a web or API key token.
type Web struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// User identifier.
	//
	// Types that are valid to be assigned to IdOneof:
	//
	//	*Web_UserId
	//	*Web_KeyId
	IdOneof isWeb_IdOneof `protobuf_oneof:"id_oneof"`
	// Organization ID (UUID).
	OrgId []byte `protobuf:"bytes,3,opt,name=org_id,json=orgId,proto3" json:"org_id,omitempty"`
	// User role.
	Role api.Role `protobuf:"varint,4,opt,name=role,proto3,enum=ownmfa.api.Role" json:"role,omitempty"`
	// Token expiration timestamp. If present, nanos should be zeroed for compactness. Will not be present for API key use.
	ExpiresAt     *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Web) Reset() {
	*x = Web{}
	mi := &file_token_ownmfa_web_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Web) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Web) ProtoMessage() {}

func (x *Web) ProtoReflect() protoreflect.Message {
	mi := &file_token_ownmfa_web_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Web.ProtoReflect.Descriptor instead.
func (*Web) Descriptor() ([]byte, []int) {
	return file_token_ownmfa_web_proto_rawDescGZIP(), []int{0}
}

func (x *Web) GetIdOneof() isWeb_IdOneof {
	if x != nil {
		return x.IdOneof
	}
	return nil
}

func (x *Web) GetUserId() []byte {
	if x != nil {
		if x, ok := x.IdOneof.(*Web_UserId); ok {
			return x.UserId
		}
	}
	return nil
}

func (x *Web) GetKeyId() []byte {
	if x != nil {
		if x, ok := x.IdOneof.(*Web_KeyId); ok {
			return x.KeyId
		}
	}
	return nil
}

func (x *Web) GetOrgId() []byte {
	if x != nil {
		return x.OrgId
	}
	return nil
}

func (x *Web) GetRole() api.Role {
	if x != nil {
		return x.Role
	}
	return api.Role(0)
}

func (x *Web) GetExpiresAt() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpiresAt
	}
	return nil
}

type isWeb_IdOneof interface {
	isWeb_IdOneof()
}

type Web_UserId struct {
	// User ID (UUID). Either user ID or key ID must be provided.
	UserId []byte `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3,oneof"`
}

type Web_KeyId struct {
	// Key ID (UUID). Either user ID or key ID must be provided.
	KeyId []byte `protobuf:"bytes,2,opt,name=key_id,json=keyId,proto3,oneof"`
}

func (*Web_UserId) isWeb_IdOneof() {}

func (*Web_KeyId) isWeb_IdOneof() {}

var File_token_ownmfa_web_proto protoreflect.FileDescriptor

var file_token_ownmfa_web_proto_rawDesc = string([]byte{
	0x0a, 0x16, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2f, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x5f, 0x77,
	0x65, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61,
	0x2e, 0x69, 0x6e, 0x74, 0x2e, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x1a, 0x15, 0x61, 0x70, 0x69, 0x2f,
	0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x5f, 0x72, 0x6f, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xbd, 0x01, 0x0a, 0x03, 0x57, 0x65, 0x62, 0x12, 0x19, 0x0a, 0x07, 0x75, 0x73,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x06, 0x75,
	0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x17, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x15,
	0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05,
	0x6f, 0x72, 0x67, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x10, 0x2e, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x39, 0x0a, 0x0a, 0x65,
	0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x65, 0x78, 0x70,
	0x69, 0x72, 0x65, 0x73, 0x41, 0x74, 0x42, 0x0a, 0x0a, 0x08, 0x69, 0x64, 0x5f, 0x6f, 0x6e, 0x65,
	0x6f, 0x66, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2f, 0x68, 0x65, 0x72, 0x6d, 0x65, 0x73, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_token_ownmfa_web_proto_rawDescOnce sync.Once
	file_token_ownmfa_web_proto_rawDescData []byte
)

func file_token_ownmfa_web_proto_rawDescGZIP() []byte {
	file_token_ownmfa_web_proto_rawDescOnce.Do(func() {
		file_token_ownmfa_web_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_token_ownmfa_web_proto_rawDesc), len(file_token_ownmfa_web_proto_rawDesc)))
	})
	return file_token_ownmfa_web_proto_rawDescData
}

var file_token_ownmfa_web_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_token_ownmfa_web_proto_goTypes = []any{
	(*Web)(nil),                   // 0: ownmfa.int.token.Web
	(api.Role)(0),                 // 1: ownmfa.api.Role
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_token_ownmfa_web_proto_depIdxs = []int32{
	1, // 0: ownmfa.int.token.Web.role:type_name -> ownmfa.api.Role
	2, // 1: ownmfa.int.token.Web.expires_at:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_token_ownmfa_web_proto_init() }
func file_token_ownmfa_web_proto_init() {
	if File_token_ownmfa_web_proto != nil {
		return
	}
	file_token_ownmfa_web_proto_msgTypes[0].OneofWrappers = []any{
		(*Web_UserId)(nil),
		(*Web_KeyId)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_token_ownmfa_web_proto_rawDesc), len(file_token_ownmfa_web_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_token_ownmfa_web_proto_goTypes,
		DependencyIndexes: file_token_ownmfa_web_proto_depIdxs,
		MessageInfos:      file_token_ownmfa_web_proto_msgTypes,
	}.Build()
	File_token_ownmfa_web_proto = out.File
	file_token_ownmfa_web_proto_goTypes = nil
	file_token_ownmfa_web_proto_depIdxs = nil
}
