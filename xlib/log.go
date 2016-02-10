package xlib

import (
	"bytes"
	"io"
	"os"
	"sync"

	"github.com/agl/xmpp-client/xmpp"
)

func SetupRawLog(filename string, xmppConfig *xmpp.Config) (err error) {
	rawLog, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}

	lock := new(sync.Mutex)
	in := rawLogger{
		out:    rawLog,
		prefix: []byte("<- "),
		lock:   lock,
	}
	out := rawLogger{
		out:    rawLog,
		prefix: []byte("-> "),
		lock:   lock,
	}
	in.other, out.other = &out, &in

	xmppConfig.InLog = &in
	xmppConfig.OutLog = &out

	defer in.flush()
	defer out.flush()
	return
}

type rawLogger struct {
	out    io.Writer
	prefix []byte
	lock   *sync.Mutex
	other  *rawLogger
	buf    []byte
}

func (r *rawLogger) Write(data []byte) (int, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if err := r.other.flush(); err != nil {
		return 0, nil
	}

	origLen := len(data)
	for len(data) > 0 {
		if newLine := bytes.IndexByte(data, '\n'); newLine >= 0 {
			r.buf = append(r.buf, data[:newLine]...)
			data = data[newLine+1:]
		} else {
			r.buf = append(r.buf, data...)
			data = nil
		}
	}

	return origLen, nil
}

func (r *rawLogger) flush() error {
	if len(r.buf) == 0 {
		return nil
	}

	if _, err := r.out.Write(r.prefix); err != nil {
		return err
	}
	if _, err := r.out.Write(r.buf); err != nil {
		return err
	}
	if _, err := r.out.Write(NEWLINE); err != nil {
		return err
	}
	r.buf = r.buf[:0]
	return nil
}

type LineLogger struct {
	xio XIO
	buf []byte
}

func (l *LineLogger) logLines(in []byte) []byte {
	for len(in) > 0 {
		if newLine := bytes.IndexByte(in, '\n'); newLine >= 0 {
			l.xio.Info(string(in[:newLine]))
			in = in[newLine+1:]
		} else {
			break
		}
	}
	return in
}

func (l *LineLogger) Write(data []byte) (int, error) {
	origLen := len(data)

	if len(l.buf) == 0 {
		data = l.logLines(data)
	}

	if len(data) > 0 {
		l.buf = append(l.buf, data...)
	}

	l.buf = l.logLines(l.buf)
	return origLen, nil
}

func NewLineLogger(xio XIO) *LineLogger {
	return &LineLogger{xio, nil}
}
