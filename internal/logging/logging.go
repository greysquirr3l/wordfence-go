// Package logging provides leveled logging for the CLI.
package logging

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/fatih/color"
)

// Level represents a logging level.
type Level int

const (
	// LevelDebug is for debug messages.
	LevelDebug Level = iota
	// LevelVerbose is for verbose messages.
	LevelVerbose
	// LevelInfo is for informational messages.
	LevelInfo
	// LevelWarning is for warning messages.
	LevelWarning
	// LevelError is for error messages.
	LevelError
	// LevelCritical is for critical messages.
	LevelCritical
)

// String returns the string representation of the level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelVerbose:
		return "VERBOSE"
	case LevelInfo:
		return "INFO"
	case LevelWarning:
		return "WARNING"
	case LevelError:
		return "ERROR"
	case LevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Logger provides leveled logging.
type Logger struct {
	mu       sync.Mutex
	level    Level
	out      io.Writer
	errOut   io.Writer
	colored  bool
	prefixed bool
}

// New creates a new Logger with the given level.
func New(level Level) *Logger {
	return &Logger{
		level:    level,
		out:      os.Stdout,
		errOut:   os.Stderr,
		colored:  true,
		prefixed: true,
	}
}

// SetLevel sets the logging level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetColored enables or disables colored output.
func (l *Logger) SetColored(colored bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.colored = colored
	color.NoColor = !colored
}

// SetPrefixed enables or disables level prefixes.
func (l *Logger) SetPrefixed(prefixed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefixed = prefixed
}

// SetOutput sets the output writer for non-error messages.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

// SetErrorOutput sets the output writer for error messages.
func (l *Logger) SetErrorOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errOut = w
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)

	var out io.Writer
	if level >= LevelWarning {
		out = l.errOut
	} else {
		out = l.out
	}

	if l.prefixed {
		var prefix string
		if l.colored {
			switch level {
			case LevelDebug:
				prefix = color.HiBlackString("[DEBUG] ")
			case LevelVerbose:
				prefix = color.CyanString("[VERBOSE] ")
			case LevelInfo:
				prefix = color.BlueString("[INFO] ")
			case LevelWarning:
				prefix = color.YellowString("[WARNING] ")
			case LevelError:
				prefix = color.RedString("[ERROR] ")
			case LevelCritical:
				prefix = color.HiRedString("[CRITICAL] ")
			}
		} else {
			prefix = fmt.Sprintf("[%s] ", level.String())
		}
		fmt.Fprintf(out, "%s%s\n", prefix, msg)
	} else {
		fmt.Fprintln(out, msg)
	}
}

// Debug logs a debug message.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, format, args...)
}

// Verbose logs a verbose message.
func (l *Logger) Verbose(format string, args ...interface{}) {
	l.log(LevelVerbose, format, args...)
}

// Info logs an informational message.
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// Warning logs a warning message.
func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(LevelWarning, format, args...)
}

// Error logs an error message.
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

// Critical logs a critical message.
func (l *Logger) Critical(format string, args ...interface{}) {
	l.log(LevelCritical, format, args...)
}

// Default logger instance.
var defaultLogger = New(LevelInfo)

// SetDefaultLevel sets the default logger level.
func SetDefaultLevel(level Level) {
	defaultLogger.SetLevel(level)
}

// SetDefaultColored enables or disables colored output on the default logger.
func SetDefaultColored(colored bool) {
	defaultLogger.SetColored(colored)
}

// SetDefaultPrefixed enables or disables level prefixes on the default logger.
func SetDefaultPrefixed(prefixed bool) {
	defaultLogger.SetPrefixed(prefixed)
}

// Debug logs a debug message to the default logger.
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

// Verbose logs a verbose message to the default logger.
func Verbose(format string, args ...interface{}) {
	defaultLogger.Verbose(format, args...)
}

// Info logs an informational message to the default logger.
func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

// Warning logs a warning message to the default logger.
func Warning(format string, args ...interface{}) {
	defaultLogger.Warning(format, args...)
}

// Error logs an error message to the default logger.
func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// Critical logs a critical message to the default logger.
func Critical(format string, args ...interface{}) {
	defaultLogger.Critical(format, args...)
}
