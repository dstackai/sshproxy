package log

import (
	"context"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type loggerKey struct{}

var defaultEntry *logrus.Entry = logrus.NewEntry(
	&logrus.Logger{
		Out: os.Stderr,
		Formatter: &logrus.TextFormatter{
			TimestampFormat: time.DateTime,
			FullTimestamp:   true,
			DisableQuote:    true,
			PadLevelText:    true,
		},
		Hooks: make(logrus.LevelHooks),
		Level: logrus.InfoLevel,
	},
)

func SetLogLevel(level string) error {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	defaultEntry.Logger.SetLevel(lvl)

	return nil
}

func WithLogger(ctx context.Context, logger *logrus.Entry) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

func GetLogger(ctx context.Context) *logrus.Entry {
	logger := ctx.Value(loggerKey{})
	if logger == nil {
		return defaultEntry
	}

	return logger.(*logrus.Entry)
}
