// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v4.24.4
// source: api/ownmfa_org.proto

package api

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
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

// Plan represents the plan and associated capabilities of an organization.
type Plan int32

const (
	// Plan is not specified.
	Plan_PLAN_UNSPECIFIED Plan = 0
	// Payment has failed and the organization is restricted to Starter plan capabilities.
	Plan_PAYMENT_FAIL Plan = 3
	// Starter plan supports software and hardware OATH one-time password authentication methods, up to a limited number of identities.
	Plan_STARTER Plan = 6
	// Pro plan supports all authentication methods and includes email support.
	Plan_PRO Plan = 9
	// Enterprise plan supports all authentication methods and includes email and phone support.
	Plan_ENTERPRISE Plan = 12
)

// Enum value maps for Plan.
var (
	Plan_name = map[int32]string{
		0:  "PLAN_UNSPECIFIED",
		3:  "PAYMENT_FAIL",
		6:  "STARTER",
		9:  "PRO",
		12: "ENTERPRISE",
	}
	Plan_value = map[string]int32{
		"PLAN_UNSPECIFIED": 0,
		"PAYMENT_FAIL":     3,
		"STARTER":          6,
		"PRO":              9,
		"ENTERPRISE":       12,
	}
)

func (x Plan) Enum() *Plan {
	p := new(Plan)
	*p = x
	return p
}

func (x Plan) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Plan) Descriptor() protoreflect.EnumDescriptor {
	return file_api_ownmfa_org_proto_enumTypes[0].Descriptor()
}

func (Plan) Type() protoreflect.EnumType {
	return &file_api_ownmfa_org_proto_enumTypes[0]
}

func (x Plan) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Plan.Descriptor instead.
func (Plan) EnumDescriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{0}
}

// Org represents an organization as stored in the database.
type Org struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Organization ID (UUID).
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Organization name.
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// Organization status.
	Status Status `protobuf:"varint,5,opt,name=status,proto3,enum=ownmfa.api.Status" json:"status,omitempty"`
	// Organization plan.
	Plan Plan `protobuf:"varint,6,opt,name=plan,proto3,enum=ownmfa.api.Plan" json:"plan,omitempty"`
	// Organization creation timestamp.
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	// Organization modification timestamp.
	UpdatedAt     *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Org) Reset() {
	*x = Org{}
	mi := &file_api_ownmfa_org_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Org) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Org) ProtoMessage() {}

func (x *Org) ProtoReflect() protoreflect.Message {
	mi := &file_api_ownmfa_org_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Org.ProtoReflect.Descriptor instead.
func (*Org) Descriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{0}
}

func (x *Org) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Org) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Org) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_STATUS_UNSPECIFIED
}

func (x *Org) GetPlan() Plan {
	if x != nil {
		return x.Plan
	}
	return Plan_PLAN_UNSPECIFIED
}

func (x *Org) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Org) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

// CreateOrgRequest is sent to create an organization.
type CreateOrgRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Org message to create.
	Org           *Org `protobuf:"bytes,1,opt,name=org,proto3" json:"org,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CreateOrgRequest) Reset() {
	*x = CreateOrgRequest{}
	mi := &file_api_ownmfa_org_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreateOrgRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateOrgRequest) ProtoMessage() {}

func (x *CreateOrgRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_ownmfa_org_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateOrgRequest.ProtoReflect.Descriptor instead.
func (*CreateOrgRequest) Descriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{1}
}

func (x *CreateOrgRequest) GetOrg() *Org {
	if x != nil {
		return x.Org
	}
	return nil
}

// GetOrgRequest is sent to get an organization.
type GetOrgRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Organization ID (UUID) to get.
	Id            string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetOrgRequest) Reset() {
	*x = GetOrgRequest{}
	mi := &file_api_ownmfa_org_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetOrgRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetOrgRequest) ProtoMessage() {}

func (x *GetOrgRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_ownmfa_org_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetOrgRequest.ProtoReflect.Descriptor instead.
func (*GetOrgRequest) Descriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{2}
}

func (x *GetOrgRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// UpdateOrgRequest is sent to update an organization.
type UpdateOrgRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Org message to update.
	Org *Org `protobuf:"bytes,1,opt,name=org,proto3" json:"org,omitempty"`
	// Fields to update. Automatically populated by a PATCH request. If not present, a full resource update is performed.
	UpdateMask    *fieldmaskpb.FieldMask `protobuf:"bytes,2,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *UpdateOrgRequest) Reset() {
	*x = UpdateOrgRequest{}
	mi := &file_api_ownmfa_org_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UpdateOrgRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateOrgRequest) ProtoMessage() {}

func (x *UpdateOrgRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_ownmfa_org_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateOrgRequest.ProtoReflect.Descriptor instead.
func (*UpdateOrgRequest) Descriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{3}
}

func (x *UpdateOrgRequest) GetOrg() *Org {
	if x != nil {
		return x.Org
	}
	return nil
}

func (x *UpdateOrgRequest) GetUpdateMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.UpdateMask
	}
	return nil
}

// DeleteOrgRequest is sent to delete an organization.
type DeleteOrgRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Organization ID (UUID) to delete.
	Id            string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DeleteOrgRequest) Reset() {
	*x = DeleteOrgRequest{}
	mi := &file_api_ownmfa_org_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeleteOrgRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteOrgRequest) ProtoMessage() {}

func (x *DeleteOrgRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_ownmfa_org_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteOrgRequest.ProtoReflect.Descriptor instead.
func (*DeleteOrgRequest) Descriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{4}
}

func (x *DeleteOrgRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// ListOrgsRequest is sent to list organizations.
type ListOrgsRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Number of organizations to retrieve in a single page. Defaults to 50 if not specified, with a maximum of 250.
	PageSize int32 `protobuf:"varint,1,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// Token of the page to retrieve. If not specified, the first page of results will be returned. To request the next page of results, use next_page_token from the previous response.
	PageToken     string `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListOrgsRequest) Reset() {
	*x = ListOrgsRequest{}
	mi := &file_api_ownmfa_org_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListOrgsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListOrgsRequest) ProtoMessage() {}

func (x *ListOrgsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_ownmfa_org_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListOrgsRequest.ProtoReflect.Descriptor instead.
func (*ListOrgsRequest) Descriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{5}
}

func (x *ListOrgsRequest) GetPageSize() int32 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListOrgsRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

// ListOrgsResponse is sent in response to an organization list.
type ListOrgsResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Org array, ordered by ascending created_at timestamp.
	Orgs []*Org `protobuf:"bytes,1,rep,name=orgs,proto3" json:"orgs,omitempty"`
	// Pagination token used to retrieve the next page of results. Not returned for the last page.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
	// Total number of organizations available.
	TotalSize     int32 `protobuf:"varint,3,opt,name=total_size,json=totalSize,proto3" json:"total_size,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListOrgsResponse) Reset() {
	*x = ListOrgsResponse{}
	mi := &file_api_ownmfa_org_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListOrgsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListOrgsResponse) ProtoMessage() {}

func (x *ListOrgsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_ownmfa_org_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListOrgsResponse.ProtoReflect.Descriptor instead.
func (*ListOrgsResponse) Descriptor() ([]byte, []int) {
	return file_api_ownmfa_org_proto_rawDescGZIP(), []int{6}
}

func (x *ListOrgsResponse) GetOrgs() []*Org {
	if x != nil {
		return x.Orgs
	}
	return nil
}

func (x *ListOrgsResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

func (x *ListOrgsResponse) GetTotalSize() int32 {
	if x != nil {
		return x.TotalSize
	}
	return 0
}

var File_api_ownmfa_org_proto protoreflect.FileDescriptor

const file_api_ownmfa_org_proto_rawDesc = "" +
	"\n" +
	"\x14api/ownmfa_org.proto\x12\n" +
	"ownmfa.api\x1a\x17api/ownmfa_status.proto\x1a\x1bgoogle/protobuf/empty.proto\x1a\x1fgoogle/protobuf/timestamp.proto\x1a google/protobuf/field_mask.proto\x1a\x1cgoogle/api/annotations.proto\x1a\x1fgoogle/api/field_behavior.proto\x1a.protoc-gen-openapiv2/options/annotations.proto\x1a\x17validate/validate.proto\"\x9c\x02\n" +
	"\x03Org\x12\x13\n" +
	"\x02id\x18\x01 \x01(\tB\x03\xe0A\x03R\x02id\x12\x1d\n" +
	"\x04name\x18\x02 \x01(\tB\t\xfaB\x06r\x04\x10\x05\x18(R\x04name\x126\n" +
	"\x06status\x18\x05 \x01(\x0e2\x12.ownmfa.api.StatusB\n" +
	"\xfaB\a\x82\x01\x04\x18\x03\x18\x06R\x06status\x12)\n" +
	"\x04plan\x18\x06 \x01(\x0e2\x10.ownmfa.api.PlanB\x03\xe0A\x03R\x04plan\x12>\n" +
	"\n" +
	"created_at\x18\x03 \x01(\v2\x1a.google.protobuf.TimestampB\x03\xe0A\x03R\tcreatedAt\x12>\n" +
	"\n" +
	"updated_at\x18\x04 \x01(\v2\x1a.google.protobuf.TimestampB\x03\xe0A\x03R\tupdatedAt\"B\n" +
	"\x10CreateOrgRequest\x12.\n" +
	"\x03org\x18\x01 \x01(\v2\x0f.ownmfa.api.OrgB\v\xe0A\x02\xfaB\x05\x8a\x01\x02\x10\x01R\x03org\",\n" +
	"\rGetOrgRequest\x12\x1b\n" +
	"\x02id\x18\x01 \x01(\tB\v\xe0A\x02\xfaB\x05r\x03\xb0\x01\x01R\x02id\"\x7f\n" +
	"\x10UpdateOrgRequest\x12.\n" +
	"\x03org\x18\x01 \x01(\v2\x0f.ownmfa.api.OrgB\v\xe0A\x02\xfaB\x05\x8a\x01\x02\x10\x01R\x03org\x12;\n" +
	"\vupdate_mask\x18\x02 \x01(\v2\x1a.google.protobuf.FieldMaskR\n" +
	"updateMask\"/\n" +
	"\x10DeleteOrgRequest\x12\x1b\n" +
	"\x02id\x18\x01 \x01(\tB\v\xe0A\x02\xfaB\x05r\x03\xb0\x01\x01R\x02id\"W\n" +
	"\x0fListOrgsRequest\x12%\n" +
	"\tpage_size\x18\x01 \x01(\x05B\b\xfaB\x05\x1a\x03\x18\xfa\x01R\bpageSize\x12\x1d\n" +
	"\n" +
	"page_token\x18\x02 \x01(\tR\tpageToken\"~\n" +
	"\x10ListOrgsResponse\x12#\n" +
	"\x04orgs\x18\x01 \x03(\v2\x0f.ownmfa.api.OrgR\x04orgs\x12&\n" +
	"\x0fnext_page_token\x18\x02 \x01(\tR\rnextPageToken\x12\x1d\n" +
	"\n" +
	"total_size\x18\x03 \x01(\x05R\ttotalSize*T\n" +
	"\x04Plan\x12\x14\n" +
	"\x10PLAN_UNSPECIFIED\x10\x00\x12\x10\n" +
	"\fPAYMENT_FAIL\x10\x03\x12\v\n" +
	"\aSTARTER\x10\x06\x12\a\n" +
	"\x03PRO\x10\t\x12\x0e\n" +
	"\n" +
	"ENTERPRISE\x10\f2\xed\x04\n" +
	"\n" +
	"OrgService\x12\x93\x01\n" +
	"\tCreateOrg\x12\x1c.ownmfa.api.CreateOrgRequest\x1a\x0f.ownmfa.api.Org\"W\x92A6J4\n" +
	"\x03201\x12-\n" +
	"\x16A successful response.\x12\x13\n" +
	"\x11\x1a\x0f.ownmfa.api.Org\x82\xd3\xe4\x93\x02\x18:\x03org\"\x11/v1/organizations\x12T\n" +
	"\x06GetOrg\x12\x19.ownmfa.api.GetOrgRequest\x1a\x0f.ownmfa.api.Org\"\x1e\x82\xd3\xe4\x93\x02\x18\x12\x16/v1/organizations/{id}\x12\x86\x01\n" +
	"\tUpdateOrg\x12\x1c.ownmfa.api.UpdateOrgRequest\x1a\x0f.ownmfa.api.Org\"J\x82\xd3\xe4\x93\x02D:\x03orgZ!:\x03org2\x1a/v1/organizations/{org.id}\x1a\x1a/v1/organizations/{org.id}\x12\x87\x01\n" +
	"\tDeleteOrg\x12\x1c.ownmfa.api.DeleteOrgRequest\x1a\x16.google.protobuf.Empty\"D\x92A#J!\n" +
	"\x03204\x12\x1a\n" +
	"\x16A successful response.\x12\x00\x82\xd3\xe4\x93\x02\x18*\x16/v1/organizations/{id}\x12`\n" +
	"\bListOrgs\x12\x1b.ownmfa.api.ListOrgsRequest\x1a\x1c.ownmfa.api.ListOrgsResponse\"\x19\x82\xd3\xe4\x93\x02\x13\x12\x11/v1/organizationsB Z\x1egithub.com/ownmfa/proto/go/apib\x06proto3"

var (
	file_api_ownmfa_org_proto_rawDescOnce sync.Once
	file_api_ownmfa_org_proto_rawDescData []byte
)

func file_api_ownmfa_org_proto_rawDescGZIP() []byte {
	file_api_ownmfa_org_proto_rawDescOnce.Do(func() {
		file_api_ownmfa_org_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_api_ownmfa_org_proto_rawDesc), len(file_api_ownmfa_org_proto_rawDesc)))
	})
	return file_api_ownmfa_org_proto_rawDescData
}

var file_api_ownmfa_org_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_ownmfa_org_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_api_ownmfa_org_proto_goTypes = []any{
	(Plan)(0),                     // 0: ownmfa.api.Plan
	(*Org)(nil),                   // 1: ownmfa.api.Org
	(*CreateOrgRequest)(nil),      // 2: ownmfa.api.CreateOrgRequest
	(*GetOrgRequest)(nil),         // 3: ownmfa.api.GetOrgRequest
	(*UpdateOrgRequest)(nil),      // 4: ownmfa.api.UpdateOrgRequest
	(*DeleteOrgRequest)(nil),      // 5: ownmfa.api.DeleteOrgRequest
	(*ListOrgsRequest)(nil),       // 6: ownmfa.api.ListOrgsRequest
	(*ListOrgsResponse)(nil),      // 7: ownmfa.api.ListOrgsResponse
	(Status)(0),                   // 8: ownmfa.api.Status
	(*timestamppb.Timestamp)(nil), // 9: google.protobuf.Timestamp
	(*fieldmaskpb.FieldMask)(nil), // 10: google.protobuf.FieldMask
	(*emptypb.Empty)(nil),         // 11: google.protobuf.Empty
}
var file_api_ownmfa_org_proto_depIdxs = []int32{
	8,  // 0: ownmfa.api.Org.status:type_name -> ownmfa.api.Status
	0,  // 1: ownmfa.api.Org.plan:type_name -> ownmfa.api.Plan
	9,  // 2: ownmfa.api.Org.created_at:type_name -> google.protobuf.Timestamp
	9,  // 3: ownmfa.api.Org.updated_at:type_name -> google.protobuf.Timestamp
	1,  // 4: ownmfa.api.CreateOrgRequest.org:type_name -> ownmfa.api.Org
	1,  // 5: ownmfa.api.UpdateOrgRequest.org:type_name -> ownmfa.api.Org
	10, // 6: ownmfa.api.UpdateOrgRequest.update_mask:type_name -> google.protobuf.FieldMask
	1,  // 7: ownmfa.api.ListOrgsResponse.orgs:type_name -> ownmfa.api.Org
	2,  // 8: ownmfa.api.OrgService.CreateOrg:input_type -> ownmfa.api.CreateOrgRequest
	3,  // 9: ownmfa.api.OrgService.GetOrg:input_type -> ownmfa.api.GetOrgRequest
	4,  // 10: ownmfa.api.OrgService.UpdateOrg:input_type -> ownmfa.api.UpdateOrgRequest
	5,  // 11: ownmfa.api.OrgService.DeleteOrg:input_type -> ownmfa.api.DeleteOrgRequest
	6,  // 12: ownmfa.api.OrgService.ListOrgs:input_type -> ownmfa.api.ListOrgsRequest
	1,  // 13: ownmfa.api.OrgService.CreateOrg:output_type -> ownmfa.api.Org
	1,  // 14: ownmfa.api.OrgService.GetOrg:output_type -> ownmfa.api.Org
	1,  // 15: ownmfa.api.OrgService.UpdateOrg:output_type -> ownmfa.api.Org
	11, // 16: ownmfa.api.OrgService.DeleteOrg:output_type -> google.protobuf.Empty
	7,  // 17: ownmfa.api.OrgService.ListOrgs:output_type -> ownmfa.api.ListOrgsResponse
	13, // [13:18] is the sub-list for method output_type
	8,  // [8:13] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_api_ownmfa_org_proto_init() }
func file_api_ownmfa_org_proto_init() {
	if File_api_ownmfa_org_proto != nil {
		return
	}
	file_api_ownmfa_status_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_api_ownmfa_org_proto_rawDesc), len(file_api_ownmfa_org_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_ownmfa_org_proto_goTypes,
		DependencyIndexes: file_api_ownmfa_org_proto_depIdxs,
		EnumInfos:         file_api_ownmfa_org_proto_enumTypes,
		MessageInfos:      file_api_ownmfa_org_proto_msgTypes,
	}.Build()
	File_api_ownmfa_org_proto = out.File
	file_api_ownmfa_org_proto_goTypes = nil
	file_api_ownmfa_org_proto_depIdxs = nil
}
