package binutils

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is a wrapper for zap.SugaredLogger.
type Logger struct {
	zLogger *zap.SugaredLogger
}

// A LoggerConfig contains the running environment
// which is either "development" or "production",
// the path of file to write the logging output to,
// and an option to explicitly enable stracktrace output.
type LoggerConfig struct {
	EnableStacktrace bool   `toml:"enable_stacktrace,omitempty"`
	Environment      string `toml:"env"`
	Path             string `toml:"path,omitempty"`
}

// NewLogger builds an instance of Logger with
// default configurations. This logger writes
// DebugLevel and above logs in development environment,
// InfoLevel and above logs in production environment
// to stderr and the file specified in conf,
// in a human-friendly format.
func NewLogger(conf *LoggerConfig) *Logger {
	zLevel := zap.NewAtomicLevel()
	switch {
	case strings.EqualFold("development", conf.Environment):
		zLevel.SetLevel(zap.DebugLevel)
	case strings.EqualFold("production", conf.Environment):
		zLevel.SetLevel(zap.InfoLevel)
	default:
		panic("Environment must be either development or production")
	}

	zOutputPaths := []string{"stderr"}
	if conf.Path != "" {
		zOutputPaths = append(zOutputPaths, conf.Path)
	}

	zConfig := &zap.Config{
		Level:             zLevel,
		Development:       false,
		Encoding:          "console",
		DisableStacktrace: !conf.EnableStacktrace, // the developer needs to explicitly enable this
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "path",
			MessageKey:     "msg",
			StacktraceKey:  "stack",
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
		},
		OutputPaths: zOutputPaths,
	}

	logger, err := zConfig.Build()
	if err != nil {
		panic(err)
	}
	return &Logger{logger.Sugar()}
}

// Debug logs a message that is most useful to debug,
// with some additional context addressed by key-value pairs.
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	if keysAndValues == nil {
		l.zLogger.Debug(msg)
	} else {
		l.zLogger.Debugw(msg, keysAndValues...)
	}
}

// Info logs a message that highlights the progress of the application
// and generally can be ignored under normal circumstances,
// with some additional context addressed by key-value pairs.
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	if keysAndValues == nil {
		l.zLogger.Info(msg)
	} else {
		l.zLogger.Infow(msg, keysAndValues...)
	}
}

// Warn logs a message that indicates potentially harmful situations,
// with some additional context addressed by key-value pairs.
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	if keysAndValues == nil {
		l.zLogger.Warn(msg)
	} else {
		l.zLogger.Warnw(msg, keysAndValues...)
	}
}

// Error logs a message that is fatal to the operation,
// but not the service or application, and forces admin intervention,
// with some additional context addressed by key-value pairs.
// This still allow the application to continue running.
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	if keysAndValues == nil {
		l.zLogger.Error(msg)
	} else {
		l.zLogger.Errorw(msg, keysAndValues...)
	}
}

// Panic logs a message that is a severe error event,
// leads the application to abort, with some additional
// context addressed by key-value pairs. It then panics.
func (l *Logger) Panic(msg string, keysAndValues ...interface{}) {
	if keysAndValues == nil {
		l.zLogger.Panic(msg)
	} else {
		l.zLogger.Panicw(msg, keysAndValues...)
	}
}

// Fatal is the same as Panic but it then calls os.Exit instead.
func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	if keysAndValues == nil {
		l.zLogger.Fatal(msg)
	} else {
		l.zLogger.Fatalw(msg, keysAndValues...)
	}
}
