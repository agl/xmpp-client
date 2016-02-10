package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/agl/xmpp-client/xmpp"
	"golang.org/x/crypto/otr"
	"golang.org/x/net/proxy"

	"github.com/agl/xmpp-client/caroots"
	"github.com/agl/xmpp-client/xlib"
)

var configFile *string = flag.String("config-file", "", "Location of the config file")
var createAccount *bool = flag.Bool("create", false, "If true, attempt to create account")

func main() {
	flag.Parse()

	xlib.XIOTerm_Init()
	defer xlib.XIOTerm_Exit()

	xio := xlib.NewXIOTerm()
	defer xio.Destroy()

	xio.Resize()

	resizeChan := make(chan os.Signal)
	go func() {
		for _ = range resizeChan {
			xio.Resize()
		}
	}()
	signal.Notify(resizeChan, syscall.SIGWINCH)

	if len(*configFile) == 0 {
		homeDir := os.Getenv("HOME")
		if len(homeDir) == 0 {
			xio.Alert("$HOME not set. Please either export $HOME or use the -config-file option.\n")
			return
		}
		persistentDir := filepath.Join(homeDir, "Persistent")
		if stat, err := os.Lstat(persistentDir); err == nil && stat.IsDir() {
			// Looks like Tails.
			homeDir = persistentDir
		}
		*configFile = filepath.Join(homeDir, ".xmpp-client")
	}

	config, err := xlib.ParseConfig(*configFile)
	if err != nil {
		xio.Alert("Failed to parse config file: " + err.Error())
		config = xlib.NewConfig(*configFile)
		if !xlib.Enroll(config, xio) {
			return
		}
		config.Save()
	}

	password := config.Password
	if len(password) == 0 {
		if password, err = xio.ReadPassword(fmt.Sprintf("Password for %s (will not be saved to disk): ", config.Account)); err != nil {
			xio.Alert("Failed to read password: " + err.Error())
			return
		}
	}

	xio.SetPrompt("> ")

	parts := strings.SplitN(config.Account, "@", 2)
	if len(parts) != 2 {
		xio.Alert("invalid username (want user@domain): " + config.Account)
		return
	}
	user := parts[0]
	domain := parts[1]

	var addr string
	addrTrusted := false

	if len(config.Server) > 0 && config.Port > 0 {
		addr = fmt.Sprintf("%s:%d", config.Server, config.Port)
		addrTrusted = true
	} else {
		if len(config.Proxies) > 0 {
			xio.Alert("Cannot connect via a proxy without Server and Port being set in the config file as an SRV lookup would leak information.")
			return
		}
		host, port, err := xmpp.Resolve(domain)
		if err != nil {
			xio.Alert("Failed to resolve XMPP server: " + err.Error())
			return
		}
		addr = fmt.Sprintf("%s:%d", host, port)
	}

	var dialer proxy.Dialer
	for i := len(config.Proxies) - 1; i >= 0; i-- {
		u, err := url.Parse(config.Proxies[i])
		if err != nil {
			xio.Alert("Failed to parse " + config.Proxies[i] + " as a URL: " + err.Error())
			return
		}
		if dialer == nil {
			dialer = proxy.Direct
		}
		if dialer, err = proxy.FromURL(u, dialer); err != nil {
			xio.Alert("Failed to parse " + config.Proxies[i] + " as a proxy: " + err.Error())
			return
		}
	}

	var certSHA256 []byte
	if len(config.ServerCertificateSHA256) > 0 {
		certSHA256, err = hex.DecodeString(config.ServerCertificateSHA256)
		if err != nil {
			xio.Alert("Failed to parse ServerCertificateSHA256 (should be hex string): " + err.Error())
			return
		}
		if len(certSHA256) != 32 {
			xio.Alert("ServerCertificateSHA256 is not 32 bytes long")
			return
		}
	}

	var createCallback xmpp.FormCallback
	if *createAccount {
		createCallback = func(title, instructions string, fields []interface{}) error {
			return promptForForm(xio, user, password, title, instructions, fields)
		}
	}

	xmppConfig := &xmpp.Config{
		Log:                     &lineLogger{xio, nil},
		CreateCallback:          createCallback,
		TrustedAddress:          addrTrusted,
		Archive:                 false,
		ServerCertificateSHA256: certSHA256,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			},
		},
	}

	if domain == "jabber.ccc.de" {
		// jabber.ccc.de uses CACert but distros are removing that root
		// certificate.
		roots := x509.NewCertPool()
		caCertRoot, err := x509.ParseCertificate(caroots.CaCertRootDER)
		if err == nil {
			xio.Alert("Temporarily trusting only CACert root for CCC Jabber server")
			roots.AddCert(caCertRoot)
			xmppConfig.TLSConfig.RootCAs = roots
		} else {
			xio.Alert("Tried to add CACert root for jabber.ccc.de but failed: " + err.Error())
		}
	}

	if len(config.RawLogFile) > 0 {
		rawLog, err := os.OpenFile(config.RawLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			xio.Alert("Failed to open raw log file: " + err.Error())
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
	}

	if dialer != nil {
		xio.Info("Making connection to " + addr + " via proxy")
		if xmppConfig.Conn, err = dialer.Dial("tcp", addr); err != nil {
			xio.Alert("Failed to connect via proxy: " + err.Error())
			return
		}
	}

	s := xlib.NewSession(config, xio)

	err = s.Dial(addr, user, domain, password, xmppConfig)
	if err != nil {
		xio.Alert("Failed to connect to XMPP server: " + err.Error())
		return
	}

	s.SignalPresence("")

	input := NewInput(xio)

	commandChan := make(chan interface{})
	go input.ProcessCommands(s, commandChan)

	stanzaChan := make(chan xmpp.Stanza)
	go s.ReadMessages(stanzaChan)

	xio.Info(fmt.Sprintf("Your fingerprint is %x", s.GetFingerprint()))

	go s.Handle()

MainLoop:
	for {
		select {
		case cmd, ok := <-commandChan:
			if !ok {
				xio.Warn("Exiting because command channel closed")
				break MainLoop
			}
			s.LastAction()
			switch cmd := cmd.(type) {
			case quitCommand:
				s.Quit()
				break MainLoop
			case versionCommand:
				s.GetVersion(cmd.User)
			case rosterCommand:
				s.Xio.Info("Current roster:")
				maxLen := 0
				roster := s.GetRoster()
				for _, item := range roster {
					if maxLen < len(item.Jid) {
						maxLen = len(item.Jid)
					}
				}

				for _, item := range roster {
					state, ok := s.GetState(item.Jid)

					line := ""
					if ok {
						line += "[*] "
					} else if cmd.OnlineOnly {
						continue
					} else {
						line += "[ ] "
					}

					line += item.Jid
					numSpaces := 1 + (maxLen - len(item.Jid))
					for i := 0; i < numSpaces; i++ {
						line += " "
					}
					line += item.Subscription + "\t" + item.Name
					if ok {
						line += "\t" + state
					}
					s.Xio.Info(line)
				}
			case rosterEditCommand:
				s.DoEditRoster()
			case rosterEditDoneCommand:
				s.DoEditDoneRoster()
			case toggleStatusUpdatesCommand:
				s.ToggleStatusUpdates()
			case confirmCommand:
				s.HandleConfirmOrDeny(cmd.User, true /* confirm */)
			case denyCommand:
				s.HandleConfirmOrDeny(cmd.User, false /* deny */)
			case addCommand:
				s.SendPresence(cmd.User, "subscribe", "" /* generate id */)
			case joinCommand:
				s.Xio.Info(fmt.Sprintf("Warning: OTR is ***NOT SUPPORTED*** for Multi-User-Chats"))
				s.JoinMUC(cmd.User, "", "")
			case leaveCommand:
				s.LeaveMUC(cmd.User)

			case msgCommand:
				s.Msg(cmd.to, cmd.msg, cmd.setPromptIsEncrypted)

			case otrCommand:
				s.Send(string(cmd.User), otr.QueryMessage)
			case otrInfoCommand:
				xio.Info(fmt.Sprintf("Your OTR fingerprint is %x", s.GetFingerprint()))
				s.PrintConversations()
			case endOTRCommand:
				s.EndConversation(cmd.User)
			case authQACommand:
				s.AuthQACommand(cmd.User, cmd.Question, cmd.Secret)
			case authOobCommand:
				s.AuthOOBCommand(cmd.User, cmd.Fingerprint)
			case awayCommand:
				s.SignalPresence("away")
			case chatCommand:
				s.SignalPresence("chat")
			case dndCommand:
				s.SignalPresence("dnd")
			case xaCommand:
				s.SignalPresence("xa")
			case onlineCommand:
				s.SignalPresence("")
			case ignoreCommand:
				s.IgnoreUser(cmd.User)
			case unignoreCommand:
				s.UnignoreUser(cmd.User)
			case ignoreListCommand:
				s.IgnoreList()
			}
		case rawStanza, ok := <-stanzaChan:
			if !ok {
				xio.Warn("Exiting because channel to server closed")
				break MainLoop
			}
			switch stanza := rawStanza.Value.(type) {
			case *xmpp.ClientMessage:
				s.ProcessClientMessage(stanza)
			case *xmpp.ClientPresence:
				s.ProcessPresence(stanza)
			case *xmpp.ClientIQ:
				if stanza.Type != "get" && stanza.Type != "set" {
					continue
				}
				reply := s.ProcessIQ(stanza)
				if reply == nil {
					reply = xmpp.ErrorReply{
						Type:  "cancel",
						Error: xmpp.ErrorBadRequest{},
					}
				}
				if err := s.SendIQReply(stanza.From, "result", stanza.Id, reply); err != nil {
					xio.Alert("Failed to send IQ message: " + err.Error())
				}
			case *xmpp.StreamError:
				var text string
				if len(stanza.Text) > 0 {
					text = stanza.Text
				} else {
					text = fmt.Sprintf("%s", stanza.Any)
				}
				xio.Alert("Exiting in response to fatal error from server: " + text)
				break MainLoop
			default:
				xio.Info(fmt.Sprintf("%s %s", rawStanza.Name, rawStanza.Value))
			}
		}
	}

	os.Stdout.Write([]byte("\n"))
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
	if _, err := r.out.Write(xlib.NEWLINE); err != nil {
		return err
	}
	r.buf = r.buf[:0]
	return nil
}

type lineLogger struct {
	xio xlib.XIO
	buf []byte
}

func (l *lineLogger) logLines(in []byte) []byte {
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

func (l *lineLogger) Write(data []byte) (int, error) {
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

// promptForForm runs an XEP-0004 form and collects responses from the user.
func promptForForm(xio xlib.XIO, user, password, title, instructions string, fields []interface{}) error {
	xio.Info("The server has requested the following information. Text that has come from the server will be shown in red.")

	var tmpDir string

	showMediaEntries := func(questionNumber int, medias [][]xmpp.Media) {
		if len(medias) == 0 {
			return
		}

		xio.Write("The following media blobs have been provided by the server with this question:\n")
		for i, media := range medias {
			for j, rep := range media {
				if j == 0 {
					xio.Write(fmt.Sprintf("  %d. ", i+1))
				} else {
					xio.Write("     ")
				}
				xio.Write(fmt.Sprintf("Data of type %s", xio.FormStringForPrinting(rep.MIMEType)))
				if len(rep.URI) > 0 {
					xio.Write(fmt.Sprintf(" at %s\n", xio.FormStringForPrinting(rep.URI)))
					continue
				}

				var fileExt string
				switch rep.MIMEType {
				case "image/png":
					fileExt = "png"
				case "image/jpeg":
					fileExt = "jpeg"
				}

				if len(tmpDir) == 0 {
					var err error
					if tmpDir, err = ioutil.TempDir("", "xmppclient"); err != nil {
						xio.Write(", but failed to create temporary directory in which to save it: " + err.Error() + "\n")
						continue
					}
				}

				filename := filepath.Join(tmpDir, fmt.Sprintf("%d-%d-%d", questionNumber, i, j))
				if len(fileExt) > 0 {
					filename = filename + "." + fileExt
				}
				out, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					xio.Write(", but failed to create file in which to save it: " + err.Error() + "\n")
					continue
				}
				out.Write(rep.Data)
				out.Close()

				xio.Write(", saved in " + filename + "\n")
			}
		}

		xio.Write("\n")
	}

	var err error
	if len(title) > 0 {
		xio.Write(fmt.Sprintf("Title: %s\n", xio.FormStringForPrinting(title)))
	}
	if len(instructions) > 0 {
		xio.Write(fmt.Sprintf("Instructions: %s\n", xio.FormStringForPrinting(instructions)))
	}

	questionNumber := 0
	for _, field := range fields {
		questionNumber++
		xio.Write("\n")

		switch field := field.(type) {
		case *xmpp.FixedFormField:
			xio.Write(xio.FormStringForPrinting(field.Text))
			xio.Write("\n")
			questionNumber--

		case *xmpp.BooleanFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)
			xio.SetPrompt("Please enter yes, y, no or n: ")

		TryAgain:
			for {
				answer, err := xio.ReadLine()
				if err != nil {
					return err
				}
				switch answer {
				case "yes", "y":
					field.Result = true
				case "no", "n":
					field.Result = false
				default:
					continue TryAgain
				}
				break
			}

		case *xmpp.TextFormField:
			switch field.Label {
			case "CAPTCHA web page":
				if strings.HasPrefix(field.Default, "http") {
					// This is a oddity of jabber.ccc.de and maybe
					// others. The URL for the capture is provided
					// as the default answer to a question. Perhaps
					// that was needed with some clients. However,
					// we support embedded media and it's confusing
					// to ask the question, so we just print the
					// URL.
					xio.Write(fmt.Sprintf("CAPTCHA web page (only if not provided below): %s\n", xio.FormStringForPrinting(field.Default)))
					questionNumber--
					continue
				}

			case "User":
				field.Result = user
				questionNumber--
				continue

			case "Password":
				field.Result = password
				questionNumber--
				continue
			}

			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			if len(field.Default) > 0 {
				xio.Write(fmt.Sprintf("Please enter response or leave blank for the default, which is '%s'\n", xio.FormStringForPrinting(field.Default)))
			} else {
				xio.Write("Please enter response")
			}
			xio.SetPrompt("> ")
			if field.Private {
				field.Result, err = xio.ReadPassword("> ")
			} else {
				field.Result, err = xio.ReadLine()
			}
			if err != nil {
				return err
			}
			if len(field.Result) == 0 {
				field.Result = field.Default
			}

		case *xmpp.MultiTextFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			xio.Write("Please enter one or more responses, terminated by an empty line\n")
			xio.SetPrompt("> ")

			for {
				line, err := xio.ReadLine()
				if err != nil {
					return err
				}
				if len(line) == 0 {
					break
				}
				field.Results = append(field.Results, line)
			}

		case *xmpp.SelectionFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			for i, opt := range field.Values {
				xio.Write(fmt.Sprintf("  %d. %s\n\n", i+1, xio.FormStringForPrinting(opt)))
			}
			xio.SetPrompt("Please enter the number of your selection: ")

		TryAgain2:
			for {
				answer, err := xio.ReadLine()
				if err != nil {
					return err
				}
				answerNum, err := strconv.Atoi(answer)
				answerNum--
				if err != nil || answerNum < 0 || answerNum >= len(field.Values) {
					xio.Write("Cannot parse that reply. Try again.")
					continue TryAgain2
				}

				field.Result = answerNum
				break
			}

		case *xmpp.MultiSelectionFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			for i, opt := range field.Values {
				xio.Write(fmt.Sprintf("  %d. %s\n\n", i+1, xio.FormStringForPrinting(opt)))
			}
			xio.SetPrompt("Please enter the numbers of zero or more of the above, separated by spaces: ")

		TryAgain3:
			for {
				answer, err := xio.ReadLine()
				if err != nil {
					return err
				}

				var candidateResults []int
				answers := strings.Fields(answer)
				for _, answerStr := range answers {
					answerNum, err := strconv.Atoi(answerStr)
					answerNum--
					if err != nil || answerNum < 0 || answerNum >= len(field.Values) {
						xio.Write("Cannot parse that reply. Please try again.")
						continue TryAgain3
					}
					for _, other := range candidateResults {
						if answerNum == other {
							xio.Write("Cannot have duplicates. Please try again.")
							continue TryAgain3
						}
					}
					candidateResults = append(candidateResults, answerNum)
				}

				field.Results = candidateResults
				break
			}
		}
	}

	if len(tmpDir) > 0 {
		os.RemoveAll(tmpDir)
	}

	return nil
}
