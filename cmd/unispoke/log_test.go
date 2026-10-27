package main

import (
	"bytes"
	"log/slog"
	"regexp"
	"testing"
)

func TestPlainHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(newPlainHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("unispoke 0.2.3 (windows/amd64)")
	logger.Debug("hidden")

	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(Z|[+-]\d{2}:\d{2}) INFO unispoke 0\.2\.3 \(windows/amd64\)\n$`)
	if !re.MatchString(buf.String()) {
		t.Fatalf("unexpected log output: %q", buf.String())
	}
}

func TestPlainHandlerReplaceAttr(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(newPlainHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				return slog.String(slog.TimeKey, "T")
			case "password":
				return slog.Attr{}
			}
			return a
		},
	}))
	logger.Info("hello", "password", "secret", "user", "alice")

	if got, want := buf.String(), "T INFO hello user=alice\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPlainHandlerSource(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(newPlainHandler(&buf, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))
	logger.Info("hi")

	re := regexp.MustCompile(` INFO source=\S+:\d+ hi\n$`)
	if !re.MatchString(buf.String()) {
		t.Fatalf("unexpected log output: %q", buf.String())
	}
}
