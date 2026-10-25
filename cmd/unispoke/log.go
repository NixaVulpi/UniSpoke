package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
)

const plainTimeLayout = "2006-01-02T15:04:05.000Z07:00"

// plainHandler 输出人类可读的单行日志。
type plainHandler struct {
	out         io.Writer
	level       slog.Leveler
	addSource   bool
	replaceAttr func([]string, slog.Attr) slog.Attr
	attrs       []slog.Attr
	groups      []string
	mu          *sync.Mutex
}

func newPlainHandler(out io.Writer, opts *slog.HandlerOptions) *plainHandler {
	h := &plainHandler{out: out, level: slog.LevelInfo, mu: new(sync.Mutex)}
	if opts != nil {
		if opts.Level != nil {
			h.level = opts.Level
		}
		h.addSource = opts.AddSource
		h.replaceAttr = opts.ReplaceAttr
	}
	return h
}

func (h *plainHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *plainHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	h.writeBuiltin(&b, slog.Time(slog.TimeKey, r.Time), r.Time.Format(plainTimeLayout))
	h.writeBuiltin(&b, slog.Any(slog.LevelKey, r.Level), r.Level.String())
	if h.addSource && r.PC != 0 {
		frame, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
		a := slog.String(slog.SourceKey, fmt.Sprintf("%s:%d", frame.File, frame.Line))
		if h.replaceAttr != nil {
			a = h.replaceAttr(h.groups, a)
		}
		if a.Key != "" {
			appendField(&b, a.Key+"="+a.Value.String())
		}
	}
	h.writeBuiltin(&b, slog.String(slog.MessageKey, r.Message), r.Message)

	for _, a := range h.attrs {
		h.writeAttr(&b, h.groups, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		h.writeAttr(&b, h.groups, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, b.String())
	return err
}

func (h *plainHandler) writeBuiltin(b *strings.Builder, a slog.Attr, def string) {
	orig := a.Value
	if h.replaceAttr != nil {
		a = h.replaceAttr(h.groups, a)
	}
	if a.Key == "" && a.Value.Kind() != slog.KindGroup {
		return
	}
	if h.replaceAttr == nil || a.Value.Equal(orig) {
		appendField(b, def)
		return
	}
	appendField(b, a.Value.String())
}

func (h *plainHandler) writeAttr(b *strings.Builder, groups []string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		if a.Key != "" {
			groups = append(append([]string(nil), groups...), a.Key)
		}
		for _, ga := range a.Value.Group() {
			h.writeAttr(b, groups, ga)
		}
		return
	}
	if h.replaceAttr != nil {
		a = h.replaceAttr(groups, a)
	}
	if a.Key == "" {
		return
	}
	appendField(b, a.Key+"="+a.Value.String())
}

func (h *plainHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	next := *h
	next.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &next
}

func (h *plainHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	next.groups = append(append([]string(nil), h.groups...), name)
	return &next
}

func appendField(b *strings.Builder, s string) {
	if b.Len() > 0 {
		b.WriteByte(' ')
	}
	b.WriteString(s)
}
