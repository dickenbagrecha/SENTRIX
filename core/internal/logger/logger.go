// Package logger configures structured logging for SENTRIX Core using log/slog.
package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Config holds logging configuration parameters.
type Config struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"` // "json" or "text"
}

// New creates and initializes a slog.Logger with the specified configuration.
func New(cfg Config, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}

	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}
