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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

type loggerContextKey struct{}

var logLevel logrus.Level = logrus.InfoLevel

func newLogger(level logrus.Level, root bool) (logrus.FieldLogger, *log.Logger, promErrorLogger) {
	if root {
		logLevel = level
	}
	l := logrus.New()
	l.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	l.SetLevel(level)

	hl := log.New(httpErrorLogger{l}, "", 0)
	pl := promErrorLogger{l}

	return l, hl, pl
}

func fromContext(ctx context.Context) logrus.FieldLogger {
	if v := ctx.Value(loggerContextKey{}); v != nil {
		if l, ok := v.(logrus.FieldLogger); ok && l != nil {
			return l
		}
	}
	l, _, _ := newLogger(logLevel, false /*root*/)
	return l
}

func intoContext(ctx context.Context, l logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, l)
}

func debug() bool {
	return logLevel >= logrus.DebugLevel
}

type httpErrorLogger struct {
	l logrus.FieldLogger
}

func (h httpErrorLogger) Write(b []byte) (n int, _ error) {
	err := fmt.Errorf("%s", string(b))
	h.l.WithError(err).Error("net/http error")
	return len(b), nil
}

type promErrorLogger struct {
	l logrus.FieldLogger
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
