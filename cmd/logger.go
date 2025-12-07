package main

import (
	"io"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// setupGlobalLogger configures the global zerolog logger for CLI usage.
func setupGlobalLogger(w io.Writer, debug bool) {
	// 1. Configure Log Level
	level := zerolog.InfoLevel
	if debug {
		level = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(level)

	// 2. Configure Output Format (Human-friendly ConsoleWriter)
	output := zerolog.ConsoleWriter{
		Out:        w,
		TimeFormat: time.Kitchen, // e.g., "3:04PM"
	}

	// 3. Set Global Logger
	log.Logger = zerolog.New(output).
		With().
		Timestamp().
		Logger()
}
