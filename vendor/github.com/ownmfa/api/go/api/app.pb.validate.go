// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: api/app.proto

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
var _app_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on App with the rules defined in the proto
// definition for this message. If any rules are violated, an error is
// returned. When asked to return all errors, validation continues after first
// violation, and the result is a list of violation errors wrapped in
// AppMultiError, or nil if none found. Otherwise, only the first error is
// returned, if any.
func (m *App) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Id

	// no validation rules for OrgId

	if l := utf8.RuneCountInString(m.GetName()); l < 5 || l > 40 {
		err := AppValidationError{
			field:  "Name",
			reason: "value length must be between 5 and 40 runes, inclusive",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if val := m.GetDigits(); val < 6 || val > 8 {
		err := AppValidationError{
			field:  "Digits",
			reason: "value must be inside range [6, 8]",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetSubjectTemplate()) > 1024 {
		err := AppValidationError{
			field:  "SubjectTemplate",
			reason: "value length must be at most 1024 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetTextBodyTemplate()) > 4096 {
		err := AppValidationError{
			field:  "TextBodyTemplate",
			reason: "value length must be at most 4096 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(m.GetHtmlBodyTemplate()) > 4096 {
		err := AppValidationError{
			field:  "HtmlBodyTemplate",
			reason: "value length must be at most 4096 bytes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if v, ok := interface{}(m.GetCreatedAt()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = AppValidationError{
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

	if v, ok := interface{}(m.GetUpdatedAt()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = AppValidationError{
				field:  "UpdatedAt",
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
		return AppMultiError(errors)
	}
	return nil
}

// AppMultiError is an error wrapping multiple validation errors returned by
// App.Validate(true) if the designated constraints aren't met.
type AppMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AppMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AppMultiError) AllErrors() []error { return m }

// AppValidationError is the validation error returned by App.Validate if the
// designated constraints aren't met.
type AppValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AppValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AppValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AppValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AppValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AppValidationError) ErrorName() string { return "AppValidationError" }

// Error satisfies the builtin error interface
func (e AppValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sApp.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AppValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AppValidationError{}

// Validate checks the field values on CreateAppRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in CreateAppRequestMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *CreateAppRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetApp() == nil {
		err := CreateAppRequestValidationError{
			field:  "App",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if v, ok := interface{}(m.GetApp()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = CreateAppRequestValidationError{
				field:  "App",
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
		return CreateAppRequestMultiError(errors)
	}
	return nil
}

// CreateAppRequestMultiError is an error wrapping multiple validation errors
// returned by CreateAppRequest.Validate(true) if the designated constraints
// aren't met.
type CreateAppRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m CreateAppRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m CreateAppRequestMultiError) AllErrors() []error { return m }

// CreateAppRequestValidationError is the validation error returned by
// CreateAppRequest.Validate if the designated constraints aren't met.
type CreateAppRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CreateAppRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CreateAppRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CreateAppRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CreateAppRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CreateAppRequestValidationError) ErrorName() string { return "CreateAppRequestValidationError" }

// Error satisfies the builtin error interface
func (e CreateAppRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCreateAppRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CreateAppRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CreateAppRequestValidationError{}

// Validate checks the field values on GetAppRequest with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned. When asked to return all errors, validation continues after
// first violation, and the result is a list of violation errors wrapped in
// GetAppRequestMultiError, or nil if none found. Otherwise, only the first
// error is returned, if any.
func (m *GetAppRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if err := m._validateUuid(m.GetId()); err != nil {
		err = GetAppRequestValidationError{
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
		return GetAppRequestMultiError(errors)
	}
	return nil
}

func (m *GetAppRequest) _validateUuid(uuid string) error {
	if matched := _app_uuidPattern.MatchString(uuid); !matched {
		return errors.New("invalid uuid format")
	}

	return nil
}

// GetAppRequestMultiError is an error wrapping multiple validation errors
// returned by GetAppRequest.Validate(true) if the designated constraints
// aren't met.
type GetAppRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m GetAppRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m GetAppRequestMultiError) AllErrors() []error { return m }

// GetAppRequestValidationError is the validation error returned by
// GetAppRequest.Validate if the designated constraints aren't met.
type GetAppRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GetAppRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GetAppRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GetAppRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GetAppRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GetAppRequestValidationError) ErrorName() string { return "GetAppRequestValidationError" }

// Error satisfies the builtin error interface
func (e GetAppRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGetAppRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GetAppRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GetAppRequestValidationError{}

// Validate checks the field values on UpdateAppRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in UpdateAppRequestMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *UpdateAppRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetApp() == nil {
		err := UpdateAppRequestValidationError{
			field:  "App",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if v, ok := interface{}(m.GetApp()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = UpdateAppRequestValidationError{
				field:  "App",
				reason: "embedded message failed validation",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
	}

	if v, ok := interface{}(m.GetUpdateMask()).(interface{ Validate(bool) error }); ok {
		if err := v.Validate(all); err != nil {
			err = UpdateAppRequestValidationError{
				field:  "UpdateMask",
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
		return UpdateAppRequestMultiError(errors)
	}
	return nil
}

// UpdateAppRequestMultiError is an error wrapping multiple validation errors
// returned by UpdateAppRequest.Validate(true) if the designated constraints
// aren't met.
type UpdateAppRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m UpdateAppRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m UpdateAppRequestMultiError) AllErrors() []error { return m }

// UpdateAppRequestValidationError is the validation error returned by
// UpdateAppRequest.Validate if the designated constraints aren't met.
type UpdateAppRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UpdateAppRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UpdateAppRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UpdateAppRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UpdateAppRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UpdateAppRequestValidationError) ErrorName() string { return "UpdateAppRequestValidationError" }

// Error satisfies the builtin error interface
func (e UpdateAppRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpdateAppRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UpdateAppRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UpdateAppRequestValidationError{}

// Validate checks the field values on DeleteAppRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in DeleteAppRequestMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *DeleteAppRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if err := m._validateUuid(m.GetId()); err != nil {
		err = DeleteAppRequestValidationError{
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
		return DeleteAppRequestMultiError(errors)
	}
	return nil
}

func (m *DeleteAppRequest) _validateUuid(uuid string) error {
	if matched := _app_uuidPattern.MatchString(uuid); !matched {
		return errors.New("invalid uuid format")
	}

	return nil
}

// DeleteAppRequestMultiError is an error wrapping multiple validation errors
// returned by DeleteAppRequest.Validate(true) if the designated constraints
// aren't met.
type DeleteAppRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DeleteAppRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DeleteAppRequestMultiError) AllErrors() []error { return m }

// DeleteAppRequestValidationError is the validation error returned by
// DeleteAppRequest.Validate if the designated constraints aren't met.
type DeleteAppRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DeleteAppRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DeleteAppRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DeleteAppRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DeleteAppRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DeleteAppRequestValidationError) ErrorName() string { return "DeleteAppRequestValidationError" }

// Error satisfies the builtin error interface
func (e DeleteAppRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDeleteAppRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DeleteAppRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DeleteAppRequestValidationError{}

// Validate checks the field values on ListAppsRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in ListAppsRequestMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *ListAppsRequest) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetPageSize() > 250 {
		err := ListAppsRequestValidationError{
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
		return ListAppsRequestMultiError(errors)
	}
	return nil
}

// ListAppsRequestMultiError is an error wrapping multiple validation errors
// returned by ListAppsRequest.Validate(true) if the designated constraints
// aren't met.
type ListAppsRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListAppsRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListAppsRequestMultiError) AllErrors() []error { return m }

// ListAppsRequestValidationError is the validation error returned by
// ListAppsRequest.Validate if the designated constraints aren't met.
type ListAppsRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListAppsRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListAppsRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListAppsRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListAppsRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListAppsRequestValidationError) ErrorName() string { return "ListAppsRequestValidationError" }

// Error satisfies the builtin error interface
func (e ListAppsRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListAppsRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListAppsRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListAppsRequestValidationError{}

// Validate checks the field values on ListAppsResponse with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned. When asked to return all errors, validation continues
// after first violation, and the result is a list of violation errors wrapped
// in ListAppsResponseMultiError, or nil if none found. Otherwise, only the
// first error is returned, if any.
func (m *ListAppsResponse) Validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetApps() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate(bool) error }); ok {
			if err := v.Validate(all); err != nil {
				err = ListAppsResponseValidationError{
					field:  fmt.Sprintf("Apps[%v]", idx),
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
		return ListAppsResponseMultiError(errors)
	}
	return nil
}

// ListAppsResponseMultiError is an error wrapping multiple validation errors
// returned by ListAppsResponse.Validate(true) if the designated constraints
// aren't met.
type ListAppsResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListAppsResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListAppsResponseMultiError) AllErrors() []error { return m }

// ListAppsResponseValidationError is the validation error returned by
// ListAppsResponse.Validate if the designated constraints aren't met.
type ListAppsResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListAppsResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListAppsResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListAppsResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListAppsResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListAppsResponseValidationError) ErrorName() string { return "ListAppsResponseValidationError" }

// Error satisfies the builtin error interface
func (e ListAppsResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListAppsResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListAppsResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListAppsResponseValidationError{}
