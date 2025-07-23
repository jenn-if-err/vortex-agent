package slog

import (
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
)

var (
	sl = slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		TimeFormat: time.DateTime,
	}))
)

func Info(msg string, args ...any) {
	sl.Info(msg, args...)
}

func Error(msg string, args ...any) {
	sl.Error(msg, args...)
}
