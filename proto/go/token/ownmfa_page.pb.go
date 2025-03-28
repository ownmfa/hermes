// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v4.24.4
// source: token/ownmfa_page.proto

package token

import (
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

// Page represents a pagination token.
type Page struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Lower or upper bound timestamp, depending on ordering. Can represent any timestamp, but primarily used for created_at and representing the start of a page.
	BoundTs *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=bound_ts,json=boundTs,proto3" json:"bound_ts,omitempty"`
	// Previous ID (UUID). Can represent any UUID-based identifier.
	PrevId        []byte `protobuf:"bytes,2,opt,name=prev_id,json=prevId,proto3" json:"prev_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Page) Reset() {
	*x = Page{}
	mi := &file_token_ownmfa_page_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Page) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Page) ProtoMessage() {}

func (x *Page) ProtoReflect() protoreflect.Message {
	mi := &file_token_ownmfa_page_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Page.ProtoReflect.Descriptor instead.
func (*Page) Descriptor() ([]byte, []int) {
	return file_token_ownmfa_page_proto_rawDescGZIP(), []int{0}
}

func (x *Page) GetBoundTs() *timestamppb.Timestamp {
	if x != nil {
		return x.BoundTs
	}
	return nil
}

func (x *Page) GetPrevId() []byte {
	if x != nil {
		return x.PrevId
	}
	return nil
}

var File_token_ownmfa_page_proto protoreflect.FileDescriptor

const file_token_ownmfa_page_proto_rawDesc = "" +
	"\n" +
	"\x17token/ownmfa_page.proto\x12\x10ownmfa.int.token\x1a\x1fgoogle/protobuf/timestamp.proto\"V\n" +
	"\x04Page\x125\n" +
	"\bbound_ts\x18\x01 \x01(\v2\x1a.google.protobuf.TimestampR\aboundTs\x12\x17\n" +
	"\aprev_id\x18\x02 \x01(\fR\x06prevIdB)Z'github.com/ownmfa/hermes/proto/go/tokenb\x06proto3"

var (
	file_token_ownmfa_page_proto_rawDescOnce sync.Once
	file_token_ownmfa_page_proto_rawDescData []byte
)

func file_token_ownmfa_page_proto_rawDescGZIP() []byte {
	file_token_ownmfa_page_proto_rawDescOnce.Do(func() {
		file_token_ownmfa_page_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_token_ownmfa_page_proto_rawDesc), len(file_token_ownmfa_page_proto_rawDesc)))
	})
	return file_token_ownmfa_page_proto_rawDescData
}

var file_token_ownmfa_page_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_token_ownmfa_page_proto_goTypes = []any{
	(*Page)(nil),                  // 0: ownmfa.int.token.Page
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_token_ownmfa_page_proto_depIdxs = []int32{
	1, // 0: ownmfa.int.token.Page.bound_ts:type_name -> google.protobuf.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_token_ownmfa_page_proto_init() }
func file_token_ownmfa_page_proto_init() {
	if File_token_ownmfa_page_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_token_ownmfa_page_proto_rawDesc), len(file_token_ownmfa_page_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_token_ownmfa_page_proto_goTypes,
		DependencyIndexes: file_token_ownmfa_page_proto_depIdxs,
		MessageInfos:      file_token_ownmfa_page_proto_msgTypes,
	}.Build()
	File_token_ownmfa_page_proto = out.File
	file_token_ownmfa_page_proto_goTypes = nil
	file_token_ownmfa_page_proto_depIdxs = nil
}
