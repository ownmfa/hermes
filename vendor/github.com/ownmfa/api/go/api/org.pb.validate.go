// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: api/org.proto

package api

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
)

// define the regex for a UUID once up-front
var _org_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on Org with the rules defined in the proto
// definition for this message. If any rules are violated, an error is returned.
func (m *Org) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Id

	if l := utf8.RuneCountInString(m.GetName()); l < 5 || l > 40 {
		return OrgValidationError{
			field:  "Name",
			reason: "value length must be between 5 and 40 runes, inclusive",
		}
	}

	if l := utf8.RuneCountInString(m.GetDisplayName()); l < 5 || l > 80 {
		return OrgValidationError{
			field:  "DisplayName",
			reason: "value length must be between 5 and 80 runes, inclusive",
		}
	}

	if err := m._validateEmail(m.GetEmail()); err != nil {
		return OrgValidationError{
			field:  "Email",
			reason: "value must be a valid email address",
			cause:  err,
		}
	}

	if v, ok := interface{}(m.GetCreatedAt()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OrgValidationError{
				field:  "CreatedAt",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetUpdatedAt()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OrgValidationError{
				field:  "UpdatedAt",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

func (m *Org) _validateHostname(host string) error {
	s := strings.ToLower(strings.TrimSuffix(host, "."))

	if len(host) > 253 {
		return errors.New("hostname cannot exceed 253 characters")
	}

	for _, part := range strings.Split(s, ".") {
		if l := len(part); l == 0 || l > 63 {
			return errors.New("hostname part must be non-empty and cannot exceed 63 characters")
		}

		if part[0] == '-' {
			return errors.New("hostname parts cannot begin with hyphens")
		}

		if part[len(part)-1] == '-' {
			return errors.New("hostname parts cannot end with hyphens")
		}

		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("hostname parts can only contain alphanumeric characters or hyphens, got %q", string(r))
			}
		}
	}

	return nil
}

func (m *Org) _validateEmail(addr string) error {
	a, err := mail.ParseAddress(addr)
	if err != nil {
		return err
	}
	addr = a.Address

	if len(addr) > 254 {
		return errors.New("email addresses cannot exceed 254 characters")
	}

	parts := strings.SplitN(addr, "@", 2)

	if len(parts[0]) > 64 {
		return errors.New("email address local phrase cannot exceed 64 characters")
	}

	return m._validateHostname(parts[1])
}

// OrgValidationError is the validation error returned by Org.Validate if the
// designated constraints aren't met.
type OrgValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e OrgValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e OrgValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e OrgValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e OrgValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e OrgValidationError) ErrorName() string { return "OrgValidationError" }

// Error satisfies the builtin error interface
func (e OrgValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sOrg.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = OrgValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = OrgValidationError{}

// Validate checks the field values on CreateOrgRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *CreateOrgRequest) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetOrg() == nil {
		return CreateOrgRequestValidationError{
			field:  "Org",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetOrg()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return CreateOrgRequestValidationError{
				field:  "Org",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// CreateOrgRequestValidationError is the validation error returned by
// CreateOrgRequest.Validate if the designated constraints aren't met.
type CreateOrgRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CreateOrgRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CreateOrgRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CreateOrgRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CreateOrgRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CreateOrgRequestValidationError) ErrorName() string { return "CreateOrgRequestValidationError" }

// Error satisfies the builtin error interface
func (e CreateOrgRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCreateOrgRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CreateOrgRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CreateOrgRequestValidationError{}

// Validate checks the field values on GetOrgRequest with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *GetOrgRequest) Validate() error {
	if m == nil {
		return nil
	}

	if err := m._validateUuid(m.GetId()); err != nil {
		return GetOrgRequestValidationError{
			field:  "Id",
			reason: "value must be a valid UUID",
			cause:  err,
		}
	}

	return nil
}

func (m *GetOrgRequest) _validateUuid(uuid string) error {
	if matched := _org_uuidPattern.MatchString(uuid); !matched {
		return errors.New("invalid uuid format")
	}

	return nil
}

// GetOrgRequestValidationError is the validation error returned by
// GetOrgRequest.Validate if the designated constraints aren't met.
type GetOrgRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GetOrgRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GetOrgRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GetOrgRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GetOrgRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GetOrgRequestValidationError) ErrorName() string { return "GetOrgRequestValidationError" }

// Error satisfies the builtin error interface
func (e GetOrgRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGetOrgRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GetOrgRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GetOrgRequestValidationError{}

// Validate checks the field values on UpdateOrgRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *UpdateOrgRequest) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetOrg() == nil {
		return UpdateOrgRequestValidationError{
			field:  "Org",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetOrg()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return UpdateOrgRequestValidationError{
				field:  "Org",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetUpdateMask()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return UpdateOrgRequestValidationError{
				field:  "UpdateMask",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// UpdateOrgRequestValidationError is the validation error returned by
// UpdateOrgRequest.Validate if the designated constraints aren't met.
type UpdateOrgRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UpdateOrgRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UpdateOrgRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UpdateOrgRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UpdateOrgRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UpdateOrgRequestValidationError) ErrorName() string { return "UpdateOrgRequestValidationError" }

// Error satisfies the builtin error interface
func (e UpdateOrgRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpdateOrgRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UpdateOrgRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UpdateOrgRequestValidationError{}

// Validate checks the field values on DeleteOrgRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *DeleteOrgRequest) Validate() error {
	if m == nil {
		return nil
	}

	if err := m._validateUuid(m.GetId()); err != nil {
		return DeleteOrgRequestValidationError{
			field:  "Id",
			reason: "value must be a valid UUID",
			cause:  err,
		}
	}

	return nil
}

func (m *DeleteOrgRequest) _validateUuid(uuid string) error {
	if matched := _org_uuidPattern.MatchString(uuid); !matched {
		return errors.New("invalid uuid format")
	}

	return nil
}

// DeleteOrgRequestValidationError is the validation error returned by
// DeleteOrgRequest.Validate if the designated constraints aren't met.
type DeleteOrgRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DeleteOrgRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DeleteOrgRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DeleteOrgRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DeleteOrgRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DeleteOrgRequestValidationError) ErrorName() string { return "DeleteOrgRequestValidationError" }

// Error satisfies the builtin error interface
func (e DeleteOrgRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDeleteOrgRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DeleteOrgRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DeleteOrgRequestValidationError{}

// Validate checks the field values on ListOrgsRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *ListOrgsRequest) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetPageSize() > 250 {
		return ListOrgsRequestValidationError{
			field:  "PageSize",
			reason: "value must be less than or equal to 250",
		}
	}

	// no validation rules for PageToken

	return nil
}

// ListOrgsRequestValidationError is the validation error returned by
// ListOrgsRequest.Validate if the designated constraints aren't met.
type ListOrgsRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListOrgsRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListOrgsRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListOrgsRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListOrgsRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListOrgsRequestValidationError) ErrorName() string { return "ListOrgsRequestValidationError" }

// Error satisfies the builtin error interface
func (e ListOrgsRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListOrgsRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListOrgsRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListOrgsRequestValidationError{}

// Validate checks the field values on ListOrgsResponse with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *ListOrgsResponse) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetOrgs() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ListOrgsResponseValidationError{
					field:  fmt.Sprintf("Orgs[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for NextPageToken

	// no validation rules for TotalSize

	return nil
}

// ListOrgsResponseValidationError is the validation error returned by
// ListOrgsResponse.Validate if the designated constraints aren't met.
type ListOrgsResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListOrgsResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListOrgsResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListOrgsResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListOrgsResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListOrgsResponseValidationError) ErrorName() string { return "ListOrgsResponseValidationError" }

// Error satisfies the builtin error interface
func (e ListOrgsResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListOrgsResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListOrgsResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListOrgsResponseValidationError{}
