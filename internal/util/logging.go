package util

import (
	"os"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/mxcd/go-config/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

type LogLevel string

const (
	Trace   LogLevel = "trace"
	Debug   LogLevel = "debug"
	Info    LogLevel = "info"
	Warn    LogLevel = "warn"
	Warning LogLevel = "warning"
	Error   LogLevel = "error"
	Err     LogLevel = "err"
)

type LoggerOptions struct {
	LogLevel LogLevel
	IsDevEnv bool
}

func NewLoggerOptionsFromEnv() *LoggerOptions {
	return &LoggerOptions{
		LogLevel: LogLevel(config.Get().String("LOG_LEVEL")),
		IsDevEnv: config.Get().Bool("DEV"),
	}
}

func InitLogger(options *LoggerOptions) error {
	setLogLevel(options)
	setLogOutput(options)
	return nil
}

func setLogOutput(options *LoggerOptions) {
	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.000Z"
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	if options.IsDevEnv {
		log.Logger = log.Logger.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			NoColor:    false,
			TimeFormat: time.RFC3339,
		}).With().Caller().Logger()
	} else {
		log.Logger = log.Logger.With().Caller().Logger()
	}
}

func setLogLevel(options *LoggerOptions) {
	if options.LogLevel == "" {
		options.LogLevel = "info"
	}
	switch options.LogLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "err":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
