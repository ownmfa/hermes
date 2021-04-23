// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: api/session.proto

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

	common "github.com/ownmfa/api/go/common"
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

	_ = common.Role(0)
)

// define the regex for a UUID once up-front
var _session_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on LoginRequest with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned. When asked to return all errors, validation continues after
// first violation, and the result is a list of violation errors wrapped in
// LoginRequestMultiError, or nil if none found. Otherwise, only the first
// error is returned, if any.
func (m *LoginRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Email

	// no validation rules for OrgName

	// no validation rules for Password

	if len(errors) > 0 {
		return LoginRequestMultiError(errors)
	}
	return nil
}

// LoginRequestMultiError is an error wrapping multiple validation errors
// returned by LoginRequest.Validate(true) if the designated constraints
// aren't met.
type LoginRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m LoginRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m LoginRequestMultiError) AllErrors() []error { return m }

// LoginRequestValidationError is the validation error returned by
// LoginRequest.Validate if the designated constraints aren't met.
type LoginRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e LoginRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e LoginRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e LoginRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e LoginRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e LoginRequestValidationError) ErrorName() string { return "LoginRequestValidationError" }

// Error satisfies the builtin error interface
func (e LoginRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sLoginRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = LoginRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = LoginRequestValidationError{}

// Validate checks the field values on LoginResponse with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned. When asked to return all errors, validation continues after
// first violation, and the result is a list of violation errors wrapped in
// LoginResponseMultiError, or nil if none found. Otherwise, only the first
// error is returned, if any.
func (m *LoginResponse) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Token

	if v, ok := interface{}(m.GetExpiresAt()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = LoginResponseValidationError{
				field:  "ExpiresAt",
				reason: "embedded message failed validation",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return LoginResponseMultiError(errors)
	}
	return nil
}

// LoginResponseMultiError is an error wrapping multiple validation errors
// returned by LoginResponse.Validate(true) if the designated constraints
// aren't met.
type LoginResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m LoginResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m LoginResponseMultiError) AllErrors() []error { return m }

// LoginResponseValidationError is the validation error returned by
// LoginResponse.Validate if the designated constraints aren't met.
type LoginResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e LoginResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e LoginResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e LoginResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e LoginResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e LoginResponseValidationError) ErrorName() string { return "LoginResponseValidationError" }

// Error satisfies the builtin error interface
func (e LoginResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sLoginResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = LoginResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = LoginResponseValidationError{}

// Validate checks the field values on Key with the rules defined in the proto
// definition for this message. If any rules are violated, an error is
// returned. When asked to return all errors, validation continues after first
// violation, and the result is a list of violation errors wrapped in
// KeyMultiError, or nil if none found. Otherwise, only the first error is
// returned, if any.
func (m *Key) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Id

	// no validation rules for OrgId

	if l := utf8.RuneCountInString(m.GetName()); l < 5 || l > 80 {
		err := KeyValidationError{
			field:  "Name",
			reason: "value length must be between 5 and 80 runes, inclusive",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if _, ok := _Key_Role_InLookup[m.GetRole()]; !ok {
		err := KeyValidationError{
			field:  "Role",
			reason: "value must be in list [4 8 12 15]",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if v, ok := interface{}(m.GetCreatedAt()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = KeyValidationError{
				field:  "CreatedAt",
				reason: "embedded message failed validation",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return KeyMultiError(errors)
	}
	return nil
}

// KeyMultiError is an error wrapping multiple validation errors returned by
// Key.Validate(true) if the designated constraints aren't met.
type KeyMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m KeyMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m KeyMultiError) AllErrors() []error { return m }

// KeyValidationError is the validation error returned by Key.Validate if the
// designated constraints aren't met.
type KeyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e KeyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e KeyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e KeyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e KeyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e KeyValidationError) ErrorName() string { return "KeyValidationError" }

// Error satisfies the builtin error interface
func (e KeyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sKey.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = KeyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = KeyValidationError{}

var _Key_Role_InLookup = map[common.Role]struct{}{
	4:  {},
	8:  {},
	12: {},
	15: {},
}

// Validate checks the field values on CreateKeyRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in CreateKeyRequestMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *CreateKeyRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetKey() == nil {
		err := CreateKeyRequestValidationError{
			field:  "Key",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if v, ok := interface{}(m.GetKey()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = CreateKeyRequestValidationError{
				field:  "Key",
				reason: "embedded message failed validation",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return CreateKeyRequestMultiError(errors)
	}
	return nil
}

// CreateKeyRequestMultiError is an error wrapping multiple validation errors
// returned by CreateKeyRequest.Validate(true) if the designated constraints
// aren't met.
type CreateKeyRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m CreateKeyRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m CreateKeyRequestMultiError) AllErrors() []error { return m }

// CreateKeyRequestValidationError is the validation error returned by
// CreateKeyRequest.Validate if the designated constraints aren't met.
type CreateKeyRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CreateKeyRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CreateKeyRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CreateKeyRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CreateKeyRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CreateKeyRequestValidationError) ErrorName() string { return "CreateKeyRequestValidationError" }

// Error satisfies the builtin error interface
func (e CreateKeyRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCreateKeyRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CreateKeyRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CreateKeyRequestValidationError{}

// Validate checks the field values on CreateKeyResponse with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in CreateKeyResponseMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *CreateKeyResponse) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if v, ok := interface{}(m.GetKey()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = CreateKeyResponseValidationError{
				field:  "Key",
				reason: "embedded message failed validation",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
	}

	// no validation rules for Token

	if len(errors) > 0 {
		return CreateKeyResponseMultiError(errors)
	}
	return nil
}

// CreateKeyResponseMultiError is an error wrapping multiple validation errors
// returned by CreateKeyResponse.Validate(true) if the designated constraints
// aren't met.
type CreateKeyResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m CreateKeyResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m CreateKeyResponseMultiError) AllErrors() []error { return m }

// CreateKeyResponseValidationError is the validation error returned by
// CreateKeyResponse.Validate if the designated constraints aren't met.
type CreateKeyResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CreateKeyResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CreateKeyResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CreateKeyResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CreateKeyResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CreateKeyResponseValidationError) ErrorName() string {
	return "CreateKeyResponseValidationError"
}

// Error satisfies the builtin error interface
func (e CreateKeyResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCreateKeyResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CreateKeyResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CreateKeyResponseValidationError{}

// Validate checks the field values on DeleteKeyRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in DeleteKeyRequestMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *DeleteKeyRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if err := m._validateUuid(m.GetId()); err != nil {
		err = DeleteKeyRequestValidationError{
			field:  "Id",
			reason: "value must be a valid UUID",
			cause:  err,
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return DeleteKeyRequestMultiError(errors)
	}
	return nil
}

func (m *DeleteKeyRequest) _validateUuid(uuid string) error {
	if matched := _session_uuidPattern.MatchString(uuid); !matched {
		return errors.New("invalid uuid format")
	}

	return nil
}

// DeleteKeyRequestMultiError is an error wrapping multiple validation errors
// returned by DeleteKeyRequest.Validate(true) if the designated constraints
// aren't met.
type DeleteKeyRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DeleteKeyRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DeleteKeyRequestMultiError) AllErrors() []error { return m }

// DeleteKeyRequestValidationError is the validation error returned by
// DeleteKeyRequest.Validate if the designated constraints aren't met.
type DeleteKeyRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DeleteKeyRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DeleteKeyRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DeleteKeyRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DeleteKeyRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DeleteKeyRequestValidationError) ErrorName() string { return "DeleteKeyRequestValidationError" }

// Error satisfies the builtin error interface
func (e DeleteKeyRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDeleteKeyRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DeleteKeyRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DeleteKeyRequestValidationError{}

// Validate checks the field values on ListKeysRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in ListKeysRequestMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *ListKeysRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetPageSize() > 250 {
		err := ListKeysRequestValidationError{
			field:  "PageSize",
			reason: "value must be less than or equal to 250",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	// no validation rules for PageToken

	if len(errors) > 0 {
		return ListKeysRequestMultiError(errors)
	}
	return nil
}

// ListKeysRequestMultiError is an error wrapping multiple validation errors
// returned by ListKeysRequest.Validate(true) if the designated constraints
// aren't met.
type ListKeysRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListKeysRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListKeysRequestMultiError) AllErrors() []error { return m }

// ListKeysRequestValidationError is the validation error returned by
// ListKeysRequest.Validate if the designated constraints aren't met.
type ListKeysRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListKeysRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListKeysRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListKeysRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListKeysRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListKeysRequestValidationError) ErrorName() string { return "ListKeysRequestValidationError" }

// Error satisfies the builtin error interface
func (e ListKeysRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListKeysRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListKeysRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListKeysRequestValidationError{}

// Validate checks the field values on ListKeysResponse with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in ListKeysResponseMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *ListKeysResponse) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetKeys() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate(bool) error }); ok {
			if err := v.Validate(all); err != nil {
				err = ListKeysResponseValidationError{
					field:  fmt.Sprintf("Keys[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
				if !all {
					return err
				}
				errors = append(errors, err)
			}
		}

	}

	// no validation rules for NextPageToken

	// no validation rules for TotalSize

	if len(errors) > 0 {
		return ListKeysResponseMultiError(errors)
	}
	return nil
}

// ListKeysResponseMultiError is an error wrapping multiple validation errors
// returned by ListKeysResponse.Validate(true) if the designated constraints
// aren't met.
type ListKeysResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListKeysResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListKeysResponseMultiError) AllErrors() []error { return m }

// ListKeysResponseValidationError is the validation error returned by
// ListKeysResponse.Validate if the designated constraints aren't met.
type ListKeysResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListKeysResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListKeysResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListKeysResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListKeysResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListKeysResponseValidationError) ErrorName() string { return "ListKeysResponseValidationError" }

// Error satisfies the builtin error interface
func (e ListKeysResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListKeysResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListKeysResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListKeysResponseValidationError{}
