package hlog

import (
	"github.com/rs/zerolog"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	SetDefault(NewConsole())
}
