package xlib

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

// appendTerminalEscaped acts like append(), but breaks terminal escape
// sequences that may be in msg.
func appendTerminalEscaped(out, msg []byte) []byte {
	for _, c := range msg {
		if c == 127 || (c < 32 && c != '\t') {
			out = append(out, '?')
		} else {
			out = append(out, c)
		}
	}
	return out
}

type XIOTerm struct {
	term *terminal.Terminal
}

func (xio *XIOTerm) terminalMessage(color []byte, msg string, critical bool) {
	line := make([]byte, 0, len(msg)+16)

	line = append(line, ' ')
	line = append(line, color...)
	line = append(line, '*')
	line = append(line, xio.term.Escape.Reset...)
	line = append(line, []byte(fmt.Sprintf(" (%s) ", time.Now().Format(time.Kitchen)))...)
	if critical {
		line = append(line, xio.term.Escape.Red...)
	}
	line = appendTerminalEscaped(line, []byte(msg))
	if critical {
		line = append(line, xio.term.Escape.Reset...)
	}
	line = append(line, '\n')
	xio.term.Write(line)
}

func (xio *XIOTerm) Info(msg string) {
	xio.terminalMessage(xio.term.Escape.Blue, msg, false)
}

func (xio *XIOTerm) Warn(msg string) {
	xio.terminalMessage(xio.term.Escape.Magenta, msg, false)
}

func (xio *XIOTerm) Alert(msg string) {
	xio.terminalMessage(xio.term.Escape.Red, msg, false)
}

func (xio *XIOTerm) Critical(msg string) {
	xio.terminalMessage(xio.term.Escape.Red, msg, true)
}

func (xio *XIOTerm) ReadPassword(msg string) (password string, err error) {
	return xio.term.ReadPassword(msg)
}

func (xio *XIOTerm) SetPrompt(prompt string) {
	xio.term.SetPrompt(prompt)
}

func (xio *XIOTerm) SetPromptEnc(target string, isEncrypted bool) {
	prompt := make([]byte, 0, len(target)+16)
	if isEncrypted {
		prompt = append(prompt, xio.term.Escape.Green...)
	} else {
		prompt = append(prompt, xio.term.Escape.Red...)
	}

	prompt = append(prompt, target...)
	prompt = append(prompt, xio.term.Escape.Reset...)
	prompt = append(prompt, '>', ' ')
	xio.SetPrompt(string(prompt))
}

func (xio *XIOTerm) Message(timestamp, from string, msg []byte, isEncrypted bool, doBell bool) {
	var line []byte

	if isEncrypted {
		line = append(line, xio.term.Escape.Green...)
	} else {
		line = append(line, xio.term.Escape.Red...)
	}

	t := fmt.Sprintf("(%s) %s: ", timestamp, from)
	line = append(line, []byte(t)...)
	line = append(line, xio.term.Escape.Reset...)
	line = appendTerminalEscaped(line, StripHTML(msg))
	line = append(line, '\n')
	if doBell {
		line = append(line, '\a')
	}
	xio.term.Write(line)
}

func (xio *XIOTerm) StatusUpdate(timestamp, from, show, status string, gone bool) {
	var line []byte
	line = append(line, []byte(fmt.Sprintf("   (%s) ", timestamp))...)
	line = append(line, xio.term.Escape.Magenta...)
	line = append(line, []byte(from)...)
	line = append(line, ':')
	line = append(line, xio.term.Escape.Reset...)
	line = append(line, ' ')
	if gone {
		line = append(line, []byte("offline")...)
	} else if len(show) > 0 {
		line = append(line, []byte(show)...)
	} else {
		line = append(line, []byte("online")...)
	}
	line = append(line, ' ')
	line = append(line, []byte(status)...)
	line = append(line, '\n')
	xio.term.Write(line)
}

// FormStringForPrinting takes a string form the form and returns an
// escaped version with codes to make it show as red.
func (xio *XIOTerm) FormStringForPrinting(s string) string {
	var line []byte

	line = append(line, xio.term.Escape.Red...)
	line = appendTerminalEscaped(line, []byte(s))
	line = append(line, xio.term.Escape.Reset...)
	return string(line)
}

func (xio *XIOTerm) Write(s string) {
	xio.term.Write([]byte(s))
}

func (xio *XIOTerm) ReadLine() (line string, err error) {
	return xio.term.ReadLine()
}

func (xio *XIOTerm) SetAutoCompleteCallback(f XIOAutoCompleteCallbackI) {
	xio.term.AutoCompleteCallback = f
}

func (xio *XIOTerm) Resize() {
	width, height, err := terminal.GetSize(0)
	if err != nil {
		return
	}
	xio.term.SetSize(width, height)
}

func NewXIOTerm(term *terminal.Terminal) (x XIO) {
	return &XIOTerm{term: term}
}
