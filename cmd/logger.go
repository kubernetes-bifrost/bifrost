// MIT License
//
// Copyright (c) 2025 kubernetes-bifrost
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

type loggerContextKey struct{}

var logLevel logrus.Level = logrus.InfoLevel

func newLogger(level logrus.Level, root bool) (logrus.FieldLogger, logr.Logger) {
	if root {
		logLevel = level
	}

	l := logrus.New()
	l.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	l.SetLevel(level)

	cl := newCtrlLogger(l)

	if root {
		ctrl.SetLogger(cl)
		klog.SetLogger(cl)
	}

	return l, cl
}

func fromContext(ctx context.Context) *logrus.FieldLogger {
	if v := ctx.Value(loggerContextKey{}); v != nil {
		if l, ok := v.(*logrus.FieldLogger); ok && l != nil {
			return l
		}
	}
	l, _ := newLogger(logLevel, false /*root*/)
	return &l
}

func intoContext(ctx context.Context, l logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, &l)
}

// ================
// net/http adapter
// ================

type httpErrorLogger struct {
	l logrus.FieldLogger
}

func newHTTPLogger(l logrus.FieldLogger) *log.Logger {
	return log.New(httpErrorLogger{l}, "", 0)
}

func (h httpErrorLogger) Write(b []byte) (n int, _ error) {
	err := fmt.Errorf("%s", strings.TrimSpace(string(b)))
	h.l.WithError(err).Error("net/http error")
	return len(b), nil
}

// ==================
// prometheus adapter
// ==================

type promErrorLogger struct {
	l logrus.FieldLogger
}

func newPromLogger(l logrus.FieldLogger) promErrorLogger {
	return promErrorLogger{l}
}

func (p promErrorLogger) Println(v ...any) {
	if len(v) != 2 {
		p.l.WithField("args", v).Error("unexpected prometheus scrape error")
		return
	}
	msg, ok := v[0].(string)
	if !ok {
		p.l.WithField("args", v).Error("unexpected prometheus scrape error")
		return
	}
	err, ok := v[1].(error)
	if !ok {
		p.l.WithField("args", v).Error("unexpected prometheus scrape error")
		return
	}

	msg = strings.TrimSuffix(msg, ":")

	var pErr prometheus.MultiError
	if !errors.As(err, &pErr) {
		p.l.WithError(err).Error(msg)
		return
	}

	p.l.WithField("errors", pErr).Error(msg)
}

// ==========================
// controller-runtime adapter
// ==========================

type ctrlLogger struct {
	l logrus.FieldLogger
}

func logrToLogrus(level int) logrus.Level {
	return logrus.Level(level + int(logrus.InfoLevel))
}

func newCtrlLogger(l logrus.FieldLogger) logr.Logger {
	return logr.New(ctrlLogger{l})
}

func (c ctrlLogger) Init(logr.RuntimeInfo) {
}

func (c ctrlLogger) Enabled(level int) bool {
	return logLevel >= logrToLogrus(level)
}

func (c ctrlLogger) WithName(name string) logr.LogSink {
	return ctrlLogger{c.l.WithField("loggerName", name)}
}

func (c ctrlLogger) WithValues(keysAndValues ...any) logr.LogSink {
	return ctrlLogger{withKeysAndValues(c.l, keysAndValues...)}
}

func (c ctrlLogger) Error(err error, msg string, keysAndValues ...any) {
	withKeysAndValues(c.l.WithError(err), keysAndValues...).Error(msg)
}

func (c ctrlLogger) Info(level int, msg string, keysAndValues ...any) {
	l := withKeysAndValues(c.l, keysAndValues...)

	lvl := logrToLogrus(level)

	if tracer, ok := l.(interface{ Trace(...any) }); ok {
		if lvl >= logrus.TraceLevel {
			tracer.Trace(msg)
			return
		}
	}

	switch {
	case lvl <= logrus.PanicLevel:
		l.Panic(msg)
	case lvl == logrus.FatalLevel:
		l.Fatal(msg)
	case lvl == logrus.ErrorLevel:
		l.Error(msg)
	case lvl == logrus.WarnLevel:
		l.Warn(msg)
	case lvl == logrus.InfoLevel:
		l.Info(msg)
	case lvl >= logrus.DebugLevel:
		l.Debug(msg)
	}
}

func withKeysAndValues(l logrus.FieldLogger, keysAndValues ...any) logrus.FieldLogger {
	m := make(logrus.Fields, len(keysAndValues)/2)
	for i := 0; i < len(keysAndValues); i += 2 {
		k, ok := keysAndValues[i].(string)
		if !ok {
			k = fmt.Sprint(keysAndValues[i])
		}
		m[k] = keysAndValues[i+1]
	}
	return l.WithFields(m)
}
