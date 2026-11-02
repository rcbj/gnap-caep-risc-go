// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import "fmt"

// Error is a config, discovery, protocol, validation, signature, or ssf failure.
type Error struct {
	Code    string
	Msg     string
	Gnap    string
	Context any
	Cont    *Continuation
	Cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Cause }

func fail(code, message string) *Error {
	return &Error{Code: code, Msg: message}
}

func failCause(code, message string, cause error) *Error {
	return &Error{Code: code, Msg: message, Cause: cause}
}

func asError(err error) *Error {
	if err == nil {
		return nil
	}
	if ge, ok := err.(*Error); ok {
		return ge
	}
	return nil
}

func wrapMsg(code string, err error) *Error {
	if ge := asError(err); ge != nil {
		return ge
	}
	return failCause(code, err.Error(), err)
}

func fmtFail(code, format string, args ...any) *Error {
	return fail(code, fmt.Sprintf(format, args...))
}
