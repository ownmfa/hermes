// Package hlog provides functions to write logs with a friendly API. An
// interface and implementation was chosen over simpler package wrappers to
// support changing implementations.
package hlog

// Logger defines the methods provided by a Log.
type Logger interface {
	// WithLevel returns a derived Logger with the level set to level.
	WithLevel(level string) Logger
	// WithField returns a derived Logger with a string field.
	WithField(key, val string) Logger

	// Debug logs a new message with debug level.
	Debug(v ...interface{})
	// Debugf logs a new formatted message with debug level.
	Debugf(format string, v ...interface{})
	// Info logs a new message with info level.
	Info(v ...interface{})
	// Infof logs a new formatted message with info level.
	Infof(format string, v ...interface{})
	// Error logs a new message with error level.
	Error(v ...interface{})
	// Errorf logs a new formatted message with error level.
	Errorf(format string, v ...interface{})
	// Fatal logs a new message with fatal level followed by a call to
	// os.Exit(1).
	Fatal(v ...interface{})
	// Fatalf logs a new formatted message with fatal level followed by a call
	// to os.Exit(1).
	Fatalf(format string, v ...interface{})
}
