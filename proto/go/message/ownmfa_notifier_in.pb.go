// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v4.24.4
// source: message/ownmfa_notifier_in.proto

package message

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

// NotifierIn represents notification metadata as used in message queues.
type NotifierIn struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Organization ID (UUID).
	OrgId string `protobuf:"bytes,1,opt,name=org_id,json=orgId,proto3" json:"org_id,omitempty"`
	// Application ID (UUID).
	AppId string `protobuf:"bytes,2,opt,name=app_id,json=appId,proto3" json:"app_id,omitempty"`
	// Identity ID (UUID).
	IdentityId string `protobuf:"bytes,3,opt,name=identity_id,json=identityId,proto3" json:"identity_id,omitempty"`
	// Trace ID (UUID).
	TraceId       []byte `protobuf:"bytes,4,opt,name=trace_id,json=traceId,proto3" json:"trace_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NotifierIn) Reset() {
	*x = NotifierIn{}
	mi := &file_message_ownmfa_notifier_in_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NotifierIn) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotifierIn) ProtoMessage() {}

func (x *NotifierIn) ProtoReflect() protoreflect.Message {
	mi := &file_message_ownmfa_notifier_in_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotifierIn.ProtoReflect.Descriptor instead.
func (*NotifierIn) Descriptor() ([]byte, []int) {
	return file_message_ownmfa_notifier_in_proto_rawDescGZIP(), []int{0}
}

func (x *NotifierIn) GetOrgId() string {
	if x != nil {
		return x.OrgId
	}
	return ""
}

func (x *NotifierIn) GetAppId() string {
	if x != nil {
		return x.AppId
	}
	return ""
}

func (x *NotifierIn) GetIdentityId() string {
	if x != nil {
		return x.IdentityId
	}
	return ""
}

func (x *NotifierIn) GetTraceId() []byte {
	if x != nil {
		return x.TraceId
	}
	return nil
}

var File_message_ownmfa_notifier_in_proto protoreflect.FileDescriptor

var file_message_ownmfa_notifier_in_proto_rawDesc = string([]byte{
	0x0a, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2f, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61,
	0x5f, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x5f, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x12, 0x6f, 0x77, 0x6e, 0x6d, 0x66, 0x61, 0x2e, 0x69, 0x6e, 0x74, 0x2e, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x76, 0x0a, 0x0a, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69,
	0x65, 0x72, 0x49, 0x6e, 0x12, 0x15, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x12, 0x15, 0x0a, 0x06, 0x61,
	0x70, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x61, 0x70, 0x70,
	0x49, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69,
	0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x74, 0x72, 0x61, 0x63, 0x65, 0x49, 0x64, 0x42, 0x2b,
	0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x77, 0x6e,
	0x6d, 0x66, 0x61, 0x2f, 0x68, 0x65, 0x72, 0x6d, 0x65, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x67, 0x6f, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
})

var (
	file_message_ownmfa_notifier_in_proto_rawDescOnce sync.Once
	file_message_ownmfa_notifier_in_proto_rawDescData []byte
)

func file_message_ownmfa_notifier_in_proto_rawDescGZIP() []byte {
	file_message_ownmfa_notifier_in_proto_rawDescOnce.Do(func() {
		file_message_ownmfa_notifier_in_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_message_ownmfa_notifier_in_proto_rawDesc), len(file_message_ownmfa_notifier_in_proto_rawDesc)))
	})
	return file_message_ownmfa_notifier_in_proto_rawDescData
}

var file_message_ownmfa_notifier_in_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_message_ownmfa_notifier_in_proto_goTypes = []any{
	(*NotifierIn)(nil), // 0: ownmfa.int.message.NotifierIn
}
var file_message_ownmfa_notifier_in_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_message_ownmfa_notifier_in_proto_init() }
func file_message_ownmfa_notifier_in_proto_init() {
	if File_message_ownmfa_notifier_in_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_message_ownmfa_notifier_in_proto_rawDesc), len(file_message_ownmfa_notifier_in_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_message_ownmfa_notifier_in_proto_goTypes,
		DependencyIndexes: file_message_ownmfa_notifier_in_proto_depIdxs,
		MessageInfos:      file_message_ownmfa_notifier_in_proto_msgTypes,
	}.Build()
	File_message_ownmfa_notifier_in_proto = out.File
	file_message_ownmfa_notifier_in_proto_goTypes = nil
	file_message_ownmfa_notifier_in_proto_depIdxs = nil
}
