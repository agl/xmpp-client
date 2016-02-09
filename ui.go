package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agl/xmpp-client/xmpp"
	"golang.org/x/crypto/otr"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/proxy"

	"github.com/agl/xmpp-client/caroots"
	"github.com/agl/xmpp-client/xlib"
)

var configFile *string = flag.String("config-file", "", "Location of the config file")
var createAccount *bool = flag.Bool("create", false, "If true, attempt to create account")

// OTRWhitespaceTagStart may be appended to plaintext messages to signal to the
// remote client that we support OTR. It should be followed by one of the
// version specific tags, below. See "Tagged plaintext messages" in
// http://www.cypherpunks.ca/otr/Protocol-v3-4.0.0.html.
var OTRWhitespaceTagStart = []byte("\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20")

var OTRWhiteSpaceTagV1 = []byte("\x20\x09\x20\x09\x20\x20\x09\x20")
var OTRWhiteSpaceTagV2 = []byte("\x20\x20\x09\x09\x20\x20\x09\x20")
var OTRWhiteSpaceTagV3 = []byte("\x20\x20\x09\x09\x20\x20\x09\x09")

var OTRWhitespaceTag = append(OTRWhitespaceTagStart, OTRWhiteSpaceTagV2...)

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

type AutoCompleteCallbackI func(line string, pos int, key rune) (string, int, bool)

type XIO interface {
	Info(msg string)
	Warn(msg string)
	//	Msg(msg string)
	Alert(msg string)
	Critical(msg string)
	ReadPassword(msg string) (password string, err error)
	SetPrompt(prompt string)
	SetPromptEnc(target string, isEncrypted bool)
	Message(timestamp, from string, msg []byte, isEncrypted bool, doBell bool)
	StatusUpdate(timestamp, from, show string, status string, gone bool)
	FormStringForPrinting(s string) string
	Write(s string)
	ReadLine() (line string, err error)
	SetAutoCompleteCallback(f AutoCompleteCallbackI)
	Resize()
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
	line = appendTerminalEscaped(line, xlib.StripHTML(msg))
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

func (xio *XIOTerm) SetAutoCompleteCallback(f AutoCompleteCallbackI) {
	xio.term.AutoCompleteCallback = f
}

func (xio *XIOTerm) Resize() {
	width, height, err := terminal.GetSize(0)
	if err != nil {
		return
	}
	xio.term.SetSize(width, height)
}

type Session struct {
	account string
	conn    *xmpp.Conn
	xio     XIO
	roster  []xmpp.RosterEntry
	input   Input
	// conversations maps from a JID (without the resource) to an OTR
	// conversation. (Note that unencrypted conversations also pass through
	// OTR.)
	conversations map[string]*otr.Conversation
	// knownStates maps from a JID (without the resource) to the last known
	// presence state of that contact. It's used to deduping presence
	// notifications.
	knownStates map[string]string
	privateKey  *otr.PrivateKey
	config      *Config
	// lastMessageFrom is the JID (without the resource) of the contact
	// that we last received a message from.
	lastMessageFrom string
	// timeouts maps from Cookies (from outstanding requests) to the
	// absolute time when that request should timeout.
	timeouts map[xmpp.Cookie]time.Time
	// pendingRosterEdit, if non-nil, contains information about a pending
	// roster edit operation.
	pendingRosterEdit *rosterEdit
	// pendingRosterChan is the channel over which roster edit information
	// is received.
	pendingRosterChan chan *rosterEdit
	// pendingSubscribes maps JID with pending subscription requests to the
	// ID if the iq for the reply.
	pendingSubscribes map[string]string
	// lastActionTime is the time at which the user last entered a command,
	// or was last notified.
	lastActionTime time.Time
	// ignored is a list of users from whom messages are currently being
	// ignored, e.g. due to doing `/ignore soandso@jabber.foo`
	ignored map[string]struct{}
}

// rosterEdit contains information about a pending roster edit. Roster edits
// occur by writing the roster to a file and inviting the user to edit the
// file.
type rosterEdit struct {
	// fileName is the name of the file containing the roster information.
	fileName string
	// roster contains the state of the roster at the time of writing the
	// file. It's what we diff against when reading the file.
	roster []xmpp.RosterEntry
	// isComplete is true if this is the result of reading an edited
	// roster, rather than a report that the file has been written.
	isComplete bool
	// contents contains the edited roster, if isComplete is true.
	contents []byte
}

func (s *Session) readMessages(stanzaChan chan<- xmpp.Stanza) {
	defer close(stanzaChan)

	for {
		stanza, err := s.conn.Next()
		if err != nil {
			s.xio.Alert(err.Error())
			return
		}
		stanzaChan <- stanza
	}
}

func NewXIOTerm(term *terminal.Terminal) (x XIO) {
	return &XIOTerm{term: term}
}

func main() {
	flag.Parse()

	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err.Error())
	}
	defer terminal.Restore(0, oldState)
	term := terminal.NewTerminal(os.Stdin, "")
	term.SetBracketedPasteMode(true)
	defer term.SetBracketedPasteMode(false)

	xio := NewXIOTerm(term)
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

	config, err := ParseConfig(*configFile)
	if err != nil {
		xio.Alert("Failed to parse config file: " + err.Error())
		config = new(Config)
		if !enroll(config, xio) {
			return
		}
		config.filename = *configFile
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

	conn, err := xmpp.Dial(addr, user, domain, password, xmppConfig)
	if err != nil {
		xio.Alert("Failed to connect to XMPP server: " + err.Error())
		return
	}

	s := Session{
		account:           config.Account,
		conn:              conn,
		xio:               xio,
		conversations:     make(map[string]*otr.Conversation),
		knownStates:       make(map[string]string),
		privateKey:        new(otr.PrivateKey),
		config:            config,
		pendingRosterChan: make(chan *rosterEdit),
		pendingSubscribes: make(map[string]string),
		lastActionTime:    time.Now(),
		// ignored contains UIDs that are currently being ignored.
		ignored: make(map[string]struct{}),
	}
	xio.Info("Fetching roster")

	//var rosterReply chan xmpp.Stanza
	rosterReply, _, err := s.conn.RequestRoster()
	if err != nil {
		xio.Alert("Failed to request roster: " + err.Error())
		return
	}

	conn.SignalPresence("")

	s.input = Input{
		xio:         xio,
		uidComplete: new(priorityList),
	}
	commandChan := make(chan interface{})
	go s.input.ProcessCommands(commandChan)

	stanzaChan := make(chan xmpp.Stanza)
	go s.readMessages(stanzaChan)

	s.privateKey.Parse(config.PrivateKey)
	s.timeouts = make(map[xmpp.Cookie]time.Time)

	xio.Info(fmt.Sprintf("Your fingerprint is %x", s.privateKey.Fingerprint()))

	ticker := time.NewTicker(1 * time.Second)

MainLoop:
	for {
		select {
		case now := <-ticker.C:
			haveExpired := false
			for _, expiry := range s.timeouts {
				if now.After(expiry) {
					haveExpired = true
					break
				}
			}
			if !haveExpired {
				continue
			}

			newTimeouts := make(map[xmpp.Cookie]time.Time)
			for cookie, expiry := range s.timeouts {
				if now.After(expiry) {
					s.conn.Cancel(cookie)
				} else {
					newTimeouts[cookie] = expiry
				}
			}
			s.timeouts = newTimeouts

		case edit := <-s.pendingRosterChan:
			if !edit.isComplete {
				s.xio.Info("Please edit " + edit.fileName + " and run /rostereditdone when complete")
				s.pendingRosterEdit = edit
				continue
			}
			if s.processEditedRoster(edit) {
				s.pendingRosterEdit = nil
			} else {
				s.xio.Alert("Please reedit file and run /rostereditdone again")
			}

		case rosterStanza, ok := <-rosterReply:
			if !ok {
				s.xio.Alert("Failed to read roster: " + err.Error())
				return
			}
			if s.roster, err = xmpp.ParseRoster(rosterStanza); err != nil {
				s.xio.Alert("Failed to parse roster: " + err.Error())
				return
			}
			for _, entry := range s.roster {
				s.input.AddUser(entry.Jid)
			}
			s.xio.Info("Roster received")

		case cmd, ok := <-commandChan:
			if !ok {
				xio.Warn("Exiting because command channel closed")
				break MainLoop
			}
			s.lastActionTime = time.Now()
			switch cmd := cmd.(type) {
			case quitCommand:
				for to, conversation := range s.conversations {
					msgs := conversation.End()
					for _, msg := range msgs {
						s.conn.Send(to, string(msg))
					}
				}
				break MainLoop
			case versionCommand:
				replyChan, cookie, err := s.conn.SendIQ(cmd.User, "get", xmpp.VersionQuery{})
				if err != nil {
					s.xio.Alert("Error sending version request: " + err.Error())
					continue
				}
				s.timeouts[cookie] = time.Now().Add(5 * time.Second)
				go s.awaitVersionReply(replyChan, cmd.User)
			case rosterCommand:
				s.xio.Info("Current roster:")
				maxLen := 0
				for _, item := range s.roster {
					if maxLen < len(item.Jid) {
						maxLen = len(item.Jid)
					}
				}

				for _, item := range s.roster {
					state, ok := s.knownStates[item.Jid]

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
					s.xio.Info(line)
				}
			case rosterEditCommand:
				if s.pendingRosterEdit != nil {
					s.xio.Warn("Aborting previous roster edit")
					s.pendingRosterEdit = nil
				}
				rosterCopy := make([]xmpp.RosterEntry, len(s.roster))
				copy(rosterCopy, s.roster)
				go s.editRoster(rosterCopy)
			case rosterEditDoneCommand:
				if s.pendingRosterEdit == nil {
					s.xio.Warn("No roster edit in progress. Use /rosteredit to start one")
					continue
				}
				go s.loadEditedRoster(*s.pendingRosterEdit)
			case toggleStatusUpdatesCommand:
				s.config.HideStatusUpdates = !s.config.HideStatusUpdates
				s.config.Save()
				// Tell the user the current state of the statuses
				if s.config.HideStatusUpdates {
					s.xio.Info("Status updates disabled")
				} else {
					s.xio.Info("Status updates enabled")
				}
			case confirmCommand:
				s.handleConfirmOrDeny(cmd.User, true /* confirm */)
			case denyCommand:
				s.handleConfirmOrDeny(cmd.User, false /* deny */)
			case addCommand:
				s.conn.SendPresence(cmd.User, "subscribe", "" /* generate id */)
			case joinCommand:
				s.xio.Info(fmt.Sprintf("Warning: OTR is ***NOT SUPPORTED*** for Multi-User-Chats"))
				s.conn.JoinMUC(cmd.User, "", "")
			case leaveCommand:
				s.conn.LeaveMUC(cmd.User)

			case msgCommand:
				conversation, ok := s.conversations[cmd.to]
				isEncrypted := ok && conversation.IsEncrypted()
				if cmd.setPromptIsEncrypted != nil {
					cmd.setPromptIsEncrypted <- isEncrypted
				}
				if !isEncrypted && config.ShouldEncryptTo(cmd.to) {
					s.xio.Warn(fmt.Sprintf("Did not send: no encryption established with %s", cmd.to))
					continue
				}
				var msgs [][]byte
				message := []byte(cmd.msg)
				// Automatically tag all outgoing plaintext
				// messages with a whitespace tag that
				// indicates that we support OTR.
				if config.OTRAutoAppendTag &&
					!bytes.Contains(message, []byte("?OTR")) &&
					(!ok || !conversation.IsEncrypted()) {
					message = append(message, OTRWhitespaceTag...)
				}
				if ok {
					var err error
					msgs, err = conversation.Send(message)
					if err != nil {
						s.xio.Alert(err.Error())
						break
					}
				} else {
					msgs = [][]byte{[]byte(message)}
				}

				for _, message := range msgs {
					s.conn.Send(cmd.to, string(message))
				}
			case otrCommand:
				s.conn.Send(string(cmd.User), otr.QueryMessage)
			case otrInfoCommand:
				xio.Info(fmt.Sprintf("Your OTR fingerprint is %x", s.privateKey.Fingerprint()))
				for to, conversation := range s.conversations {
					if conversation.IsEncrypted() {
						s.xio.Info(fmt.Sprintf("Secure session with %s underway:", to))
						printConversationInfo(&s, to, conversation)
					}
				}
			case endOTRCommand:
				to := string(cmd.User)
				conversation, ok := s.conversations[to]
				if !ok {
					s.xio.Alert("No secure session established")
					break
				}
				msgs := conversation.End()
				for _, msg := range msgs {
					s.conn.Send(to, string(msg))
				}
				s.input.SetPromptForTarget(cmd.User, false)
				s.xio.Warn("OTR conversation ended with " + cmd.User)
			case authQACommand:
				to := string(cmd.User)
				conversation, ok := s.conversations[to]
				if !ok {
					s.xio.Alert("Can't authenticate without a secure conversation established")
					break
				}
				msgs, err := conversation.Authenticate(cmd.Question, []byte(cmd.Secret))
				if err != nil {
					s.xio.Alert("Error while starting authentication with " + to + ": " + err.Error())
				}
				for _, msg := range msgs {
					s.conn.Send(to, string(msg))
				}
			case authOobCommand:
				fpr, err := hex.DecodeString(cmd.Fingerprint)
				if err != nil {
					s.xio.Alert(fmt.Sprintf("Invalid fingerprint %s - not authenticated", cmd.Fingerprint))
					break
				}
				existing := s.config.UserIdForFingerprint(fpr)
				if len(existing) != 0 {
					s.xio.Alert(fmt.Sprintf("Fingerprint %s already belongs to %s", cmd.Fingerprint, existing))
					break
				}
				s.config.KnownFingerprints = append(s.config.KnownFingerprints, KnownFingerprint{fingerprint: fpr, UserId: cmd.User})
				s.config.Save()
				s.xio.Info(fmt.Sprintf("Saved manually verified fingerprint %s for %s", cmd.Fingerprint, cmd.User))
			case awayCommand:
				s.conn.SignalPresence("away")
			case chatCommand:
				s.conn.SignalPresence("chat")
			case dndCommand:
				s.conn.SignalPresence("dnd")
			case xaCommand:
				s.conn.SignalPresence("xa")
			case onlineCommand:
				s.conn.SignalPresence("")
			case ignoreCommand:
				s.ignoreUser(cmd.User)
			case unignoreCommand:
				s.unignoreUser(cmd.User)
			case ignoreListCommand:
				s.ignoreList()
			}
		case rawStanza, ok := <-stanzaChan:
			if !ok {
				xio.Warn("Exiting because channel to server closed")
				break MainLoop
			}
			switch stanza := rawStanza.Value.(type) {
			case *xmpp.ClientMessage:
				s.processClientMessage(stanza)
			case *xmpp.ClientPresence:
				s.processPresence(stanza)
			case *xmpp.ClientIQ:
				if stanza.Type != "get" && stanza.Type != "set" {
					continue
				}
				reply := s.processIQ(stanza)
				if reply == nil {
					reply = xmpp.ErrorReply{
						Type:  "cancel",
						Error: xmpp.ErrorBadRequest{},
					}
				}
				if err := s.conn.SendIQReply(stanza.From, "result", stanza.Id, reply); err != nil {
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

func (s *Session) processIQ(stanza *xmpp.ClientIQ) interface{} {
	buf := bytes.NewBuffer(stanza.Query)
	parser := xml.NewDecoder(buf)
	token, _ := parser.Token()
	if token == nil {
		return nil
	}
	startElem, ok := token.(xml.StartElement)
	if !ok {
		return nil
	}
	switch startElem.Name.Space + " " + startElem.Name.Local {
	case "http://jabber.org/protocol/disco#info query":
		return xmpp.DiscoveryReply{
			Identities: []xmpp.DiscoveryIdentity{
				{
					Category: "client",
					Type:     "pc",
					Name:     s.config.Account,
				},
			},
		}
	case "jabber:iq:version query":
		return xmpp.VersionReply{
			Name:    "testing",
			Version: "version",
			OS:      "none",
		}
	case "jabber:iq:roster query":
		if len(stanza.From) > 0 && stanza.From != s.account {
			s.xio.Warn("Ignoring roster IQ from bad address: " + stanza.From)
			return nil
		}
		var roster xmpp.Roster
		if err := xml.NewDecoder(bytes.NewBuffer(stanza.Query)).Decode(&roster); err != nil || len(roster.Item) == 0 {
			s.xio.Warn("Failed to parse roster push IQ")
			return nil
		}
		entry := roster.Item[0]

		if entry.Subscription == "remove" {
			for i, rosterEntry := range s.roster {
				if rosterEntry.Jid == entry.Jid {
					copy(s.roster[i:], s.roster[i+1:])
					s.roster = s.roster[:len(s.roster)-1]
				}
			}
			return xmpp.EmptyReply{}
		}

		found := false
		for i, rosterEntry := range s.roster {
			if rosterEntry.Jid == entry.Jid {
				s.roster[i] = entry
				found = true
				break
			}
		}
		if !found {
			s.roster = append(s.roster, entry)
			s.input.AddUser(entry.Jid)
		}
		return xmpp.EmptyReply{}
	default:
		s.xio.Info("Unknown IQ: " + startElem.Name.Space + " " + startElem.Name.Local)
	}

	return nil
}

func (s *Session) handleConfirmOrDeny(jid string, isConfirm bool) {
	id, ok := s.pendingSubscribes[jid]
	if !ok {
		s.xio.Warn("No pending subscription from " + jid)
		return
	}
	delete(s.pendingSubscribes, id)
	typ := "unsubscribed"
	if isConfirm {
		typ = "subscribed"
	}
	if err := s.conn.SendPresence(jid, typ, id); err != nil {
		s.xio.Alert("Error sending presence stanza: " + err.Error())
	}
}

func (s *Session) ignoreUser(uid string) {
	if _, ok := s.ignored[uid]; ok {
		s.input.xio.Info("Already ignoring " + uid)
		return
	}

	s.input.lock.Lock()
	defer s.input.lock.Unlock()

	hasContact := false

	for _, existingUid := range s.input.uids {
		if existingUid == uid {
			hasContact = true
		}
	}

	if hasContact {
		s.input.xio.Info(fmt.Sprintf("Ignoring messages from %s for the duration of this session", uid))
	} else {
		s.input.xio.Warn(fmt.Sprintf("%s isn't in your contact list... ignoring anyway for the duration of this session!", uid))
	}

	s.ignored[uid] = struct{}{}
	s.input.xio.Info(fmt.Sprintf("Use '/unignore %s' to continue receiving messages from them.", uid))
}

func (s *Session) unignoreUser(uid string) {
	if _, ok := s.ignored[uid]; !ok {
		s.input.xio.Info("No ignore registered for " + uid)
		return
	}

	s.input.xio.Info("No longer ignoring messages from " + uid)
	delete(s.ignored, uid)
}

func (s *Session) ignoreList() {
	var ignored []string

	for ignoredUser, _ := range s.ignored {
		ignored = append(ignored, ignoredUser)
	}
	sort.Strings(ignored)

	s.input.xio.Info("Ignoring messages from these users for the duration of the session:")
	for _, ignoredUser := range ignored {
		s.xio.Info("  " + ignoredUser)
	}
}

func (s *Session) processClientMessage(stanza *xmpp.ClientMessage) {
	from := xmpp.RemoveResourceFromJid(stanza.From)

	if _, ok := s.ignored[from]; ok {
		return
	}

	if stanza.Type == "error" {
		s.xio.Alert("Error reported from " + from + ": " + stanza.Body)
		return
	}

	conversation, ok := s.conversations[from]
	if !ok {
		conversation = new(otr.Conversation)
		conversation.PrivateKey = s.privateKey
		s.conversations[from] = conversation
	}

	out, encrypted, change, toSend, err := conversation.Receive([]byte(stanza.Body))
	if err != nil {
		s.xio.Alert("While processing message from " + from + ": " + err.Error())
		s.conn.Send(stanza.From, otr.ErrorPrefix+"Error processing message")
	}
	for _, msg := range toSend {
		s.conn.Send(stanza.From, string(msg))
	}
	switch change {
	case otr.NewKeys:
		s.input.SetPromptForTarget(from, true)
		s.xio.Info(fmt.Sprintf("New OTR session with %s established", from))
		printConversationInfo(s, from, conversation)
	case otr.ConversationEnded:
		s.input.SetPromptForTarget(from, false)
		// This is probably unsafe without a policy that _forces_ crypto to
		// _everyone_ by default and refuses plaintext. Users might not notice
		// their buddy has ended a session, which they have also ended, and they
		// might send a plain text message. So we should ensure they _want_ this
		// feature and have set it as an explicit preference.
		if s.config.OTRAutoTearDown {
			if s.conversations[from] == nil {
				s.xio.Alert(fmt.Sprintf("No secure session established; unable to automatically tear down OTR conversation with %s.", from))
				break
			} else {
				s.xio.Info(fmt.Sprintf("%s has ended the secure conversation.", from))
				msgs := conversation.End()
				for _, msg := range msgs {
					s.conn.Send(from, string(msg))
				}
				s.xio.Info(fmt.Sprintf("Secure session with %s has been automatically ended. Messages will be sent in the clear until another OTR session is established.", from))
			}
		} else {
			s.xio.Info(fmt.Sprintf("%s has ended the secure conversation. You should do likewise with /otr-end %s", from, from))
		}
	case otr.SMPSecretNeeded:
		s.xio.Info(fmt.Sprintf("%s is attempting to authenticate. Please supply mutual shared secret with /otr-auth user secret", from))
		if question := conversation.SMPQuestion(); len(question) > 0 {
			s.xio.Info(fmt.Sprintf("%s asks: %s", from, question))
		}
	case otr.SMPComplete:
		s.xio.Info(fmt.Sprintf("Authentication with %s successful", from))
		fpr := conversation.TheirPublicKey.Fingerprint()
		if len(s.config.UserIdForFingerprint(fpr)) == 0 {
			s.config.KnownFingerprints = append(s.config.KnownFingerprints, KnownFingerprint{fingerprint: fpr, UserId: from})
		}
		s.config.Save()
	case otr.SMPFailed:
		s.xio.Alert(fmt.Sprintf("Authentication with %s failed", from))
	}

	if len(out) == 0 {
		return
	}

	detectedOTRVersion := 0
	// We don't need to alert about tags encoded inside of messages that are
	// already encrypted with OTR
	whitespaceTagLength := len(OTRWhitespaceTagStart) + len(OTRWhiteSpaceTagV1)
	if !encrypted && len(out) >= whitespaceTagLength {
		whitespaceTag := out[len(out)-whitespaceTagLength:]
		if bytes.Equal(whitespaceTag[:len(OTRWhitespaceTagStart)], OTRWhitespaceTagStart) {
			if bytes.HasSuffix(whitespaceTag, OTRWhiteSpaceTagV1) {
				s.xio.Info(fmt.Sprintf("%s appears to support OTRv1. You should encourage them to upgrade their OTR client!", from))
				detectedOTRVersion = 1
			}
			if bytes.HasSuffix(whitespaceTag, OTRWhiteSpaceTagV2) {
				detectedOTRVersion = 2
			}
			if bytes.HasSuffix(whitespaceTag, OTRWhiteSpaceTagV3) {
				detectedOTRVersion = 3
			}
		}
	}

	// MultiParty OTR does not exist yet unfortunately
	// Thus do not note we are going to try it
	if stanza.Type == "groupchat" {
		detectedOTRVersion = 0
	}

	if s.config.OTRAutoStartSession && detectedOTRVersion >= 2 {
		s.xio.Info(fmt.Sprintf("%s appears to support OTRv%d. We are attempting to start an OTR session with them.", from, detectedOTRVersion))
		s.conn.Send(from, otr.QueryMessage)
	} else if s.config.OTRAutoStartSession && detectedOTRVersion == 1 {
		s.xio.Info(fmt.Sprintf("%s appears to support OTRv%d. You should encourage them to upgrade their OTR client!", from, detectedOTRVersion))
	}

	var timestamp string
	var messageTime time.Time
	if stanza.Delay != nil && len(stanza.Delay.Stamp) > 0 {
		// An XEP-0203 Delayed Delivery <delay/> element exists for
		// this message, meaning that someone sent it while we were
		// offline. Let's show the timestamp for when the message was
		// sent, rather than time.Now().
		messageTime, err = time.Parse(time.RFC3339, stanza.Delay.Stamp)
		if err != nil {
			s.xio.Alert("Can not parse Delayed Delivery timestamp, using quoted string instead.")
			timestamp = fmt.Sprintf("%q", stanza.Delay.Stamp)
		}
	} else {
		messageTime = time.Now()
	}
	if len(timestamp) == 0 {
		timestamp = messageTime.Format(time.Stamp)
	}

	s.xio.Message(timestamp, from, out, encrypted, s.config.Bell)
	s.maybeNotify()
}

func (s *Session) maybeNotify() {
	now := time.Now()
	idleThreshold := s.config.IdleSecondsBeforeNotification
	if idleThreshold == 0 {
		idleThreshold = 60
	}
	notifyTime := s.lastActionTime.Add(time.Duration(idleThreshold) * time.Second)
	if now.Before(notifyTime) {
		return
	}

	s.lastActionTime = now
	if len(s.config.NotifyCommand) == 0 {
		return
	}

	cmd := exec.Command(s.config.NotifyCommand[0], s.config.NotifyCommand[1:]...)
	go func() {
		if err := cmd.Run(); err != nil {
			s.xio.Alert("Failed to run notify command: " + err.Error())
		}
	}()
}

func isAwayStatus(status string) bool {
	switch status {
	case "xa", "away":
		return true
	}
	return false
}

func (s *Session) processPresence(stanza *xmpp.ClientPresence) {
	gone := false

	switch stanza.Type {
	case "subscribe":
		// This is a subscription request
		jid := xmpp.RemoveResourceFromJid(stanza.From)
		s.xio.Info(jid + " wishes to see when you're online. Use '/confirm " + jid + "' to confirm (or likewise with /deny to decline)")
		s.pendingSubscribes[jid] = stanza.Id
		s.input.AddUser(jid)
		return
	case "unavailable":
		gone = true
	case "":
		break
	default:
		return
	}

	from := xmpp.RemoveResourceFromJid(stanza.From)

	if gone {
		if _, ok := s.knownStates[from]; !ok {
			// They've gone, but we never knew they were online.
			return
		}
		delete(s.knownStates, from)
	} else {
		if _, ok := s.knownStates[from]; !ok && isAwayStatus(stanza.Show) {
			// Skip people who are initially away.
			return
		}

		if lastState, ok := s.knownStates[from]; ok && lastState == stanza.Show {
			// No change. Ignore.
			return
		}
		s.knownStates[from] = stanza.Show
	}

	if !s.config.HideStatusUpdates {
		timestamp := time.Now().Format(time.Kitchen)
		s.xio.StatusUpdate(timestamp, from, stanza.Show, stanza.Status, gone)
	}
}

func (s *Session) awaitVersionReply(ch <-chan xmpp.Stanza, user string) {
	stanza, ok := <-ch
	if !ok {
		s.xio.Warn("Version request to " + user + " timed out")
		return
	}
	reply, ok := stanza.Value.(*xmpp.ClientIQ)
	if !ok {
		s.xio.Warn("Version request to " + user + " resulted in bad reply type")
		return
	}

	if reply.Type == "error" {
		s.xio.Warn("Version request to " + user + " resulted in XMPP error")
		return
	} else if reply.Type != "result" {
		s.xio.Warn("Version request to " + user + " resulted in response with unknown type: " + reply.Type)
		return
	}

	buf := bytes.NewBuffer(reply.Query)
	var versionReply xmpp.VersionReply
	if err := xml.NewDecoder(buf).Decode(&versionReply); err != nil {
		s.xio.Warn("Failed to parse version reply from " + user + ": " + err.Error())
		return
	}

	s.xio.Info(fmt.Sprintf("Version reply from %s: %#v", user, versionReply))
}

// editRoster runs in a goroutine and writes the roster to a file that the user
// can edit.
func (s *Session) editRoster(roster []xmpp.RosterEntry) {
	// In case the editor rewrites the file, we work inside a temp
	// directory.
	dir, err := ioutil.TempDir("" /* system default temp dir */, "xmpp-client")
	if err != nil {
		s.xio.Alert("Failed to create temp dir to edit roster: " + err.Error())
		return
	}

	mode, err := os.Stat(dir)
	if err != nil || mode.Mode()&os.ModePerm != 0700 {
		panic("broken system libraries gave us an insecure temp dir")
	}

	fileName := filepath.Join(dir, "roster")
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		s.xio.Alert("Failed to create temp file: " + err.Error())
		return
	}

	io.WriteString(f, `# Use this file to edit your roster.
# The file is tab deliminated and you need to preserve that. Otherwise you
# can delete lines to remove roster entries, add lines to subscribe (only
# the account is needed when adding a line) and change lines to change the
# corresponding entry.

# Once you are done, use the /rostereditdone command to process the result.

# Since there are multiple levels of unspecified character encoding, we give up
# and hex escape anything outside of printable ASCII in "\x01" form.

`)

	// Calculate the number of tabs which covers the longest escaped JID.
	maxLen := 0
	escapedJids := make([]string, len(roster))
	for i, item := range roster {
		escapedJids[i] = xlib.EscapeNonASCII(item.Jid)
		if l := len(escapedJids[i]); l > maxLen {
			maxLen = l
		}
	}
	tabs := (maxLen + 7) / 8

	for i, item := range s.roster {
		line := escapedJids[i]
		tabsUsed := len(escapedJids[i]) / 8

		if len(item.Name) > 0 || len(item.Group) > 0 {
			// We're going to put something else on the line to tab
			// across to the next column.
			for i := 0; i < tabs-tabsUsed; i++ {
				line += "\t"
			}
		}

		if len(item.Name) > 0 {
			line += "name:" + xlib.EscapeNonASCII(item.Name)
			if len(item.Group) > 0 {
				line += "\t"
			}
		}

		for j, group := range item.Group {
			if j > 0 {
				line += "\t"
			}
			line += "group:" + xlib.EscapeNonASCII(group)
		}
		line += "\n"
		io.WriteString(f, line)
	}
	f.Close()

	s.pendingRosterChan <- &rosterEdit{
		fileName: fileName,
		roster:   roster,
	}
}

func (s *Session) loadEditedRoster(edit rosterEdit) {
	contents, err := ioutil.ReadFile(edit.fileName)
	if err != nil {
		s.xio.Alert("Failed to load edited roster: " + err.Error())
		return
	}
	os.Remove(edit.fileName)
	os.Remove(filepath.Dir(edit.fileName))

	edit.isComplete = true
	edit.contents = contents
	s.pendingRosterChan <- &edit
}

func (s *Session) processEditedRoster(edit *rosterEdit) bool {
	parsedRoster := make(map[string]xmpp.RosterEntry)
	lines := bytes.Split(edit.contents, newLine)
	tab := []byte{'\t'}

	// Parse roster entries from the file.
	for i, line := range lines {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		parts := bytes.Split(line, tab)

		var entry xmpp.RosterEntry
		var err error

		if entry.Jid, err = xlib.UnescapeNonASCII(string(string(parts[0]))); err != nil {
			s.xio.Alert(fmt.Sprintf("Failed to parse JID on line %d: %s", i+1, err))
			return false
		}
		for _, part := range parts[1:] {
			if len(part) == 0 {
				continue
			}

			pos := bytes.IndexByte(part, ':')
			if pos == -1 {
				s.xio.Alert(fmt.Sprintf("Failed to find colon in item on line %d", i+1))
				return false
			}

			typ := string(part[:pos])
			value, err := xlib.UnescapeNonASCII(string(part[pos+1:]))
			if err != nil {
				s.xio.Alert(fmt.Sprintf("Failed to unescape item on line %d: %s", i+1, err))
				return false
			}

			switch typ {
			case "name":
				if len(entry.Name) > 0 {
					s.xio.Alert(fmt.Sprintf("Multiple names given for contact on line %d", i+1))
					return false
				}
				entry.Name = value
			case "group":
				if len(value) > 0 {
					entry.Group = append(entry.Group, value)
				}
			default:
				s.xio.Alert(fmt.Sprintf("Unknown item tag '%s' on line %d", typ, i+1))
				return false
			}
		}

		parsedRoster[entry.Jid] = entry
	}

	// Now diff them from the original roster
	var toDelete []string
	var toEdit []xmpp.RosterEntry
	var toAdd []xmpp.RosterEntry

	for _, entry := range edit.roster {
		newEntry, ok := parsedRoster[entry.Jid]
		if !ok {
			toDelete = append(toDelete, entry.Jid)
			continue
		}
		if newEntry.Name != entry.Name || !setEqual(newEntry.Group, entry.Group) {
			toEdit = append(toEdit, newEntry)
		}
	}

NextAdd:
	for jid, newEntry := range parsedRoster {
		for _, entry := range edit.roster {
			if entry.Jid == jid {
				continue NextAdd
			}
		}
		toAdd = append(toAdd, newEntry)
	}

	for _, jid := range toDelete {
		s.xio.Info("Deleting roster entry for " + jid)
		_, _, err := s.conn.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:          jid,
				Subscription: "remove",
			},
		})
		if err != nil {
			s.xio.Alert("Failed to remove roster entry: " + err.Error())
		}

		// Filter out any known fingerprints.
		newKnownFingerprints := make([]KnownFingerprint, 0, len(s.config.KnownFingerprints))
		for _, fpr := range s.config.KnownFingerprints {
			if fpr.UserId == jid {
				continue
			}
			newKnownFingerprints = append(newKnownFingerprints, fpr)
		}
		s.config.KnownFingerprints = newKnownFingerprints
		s.config.Save()
	}

	for _, entry := range toEdit {
		s.xio.Info("Updating roster entry for " + entry.Jid)
		_, _, err := s.conn.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:   entry.Jid,
				Name:  entry.Name,
				Group: entry.Group,
			},
		})
		if err != nil {
			s.xio.Alert("Failed to update roster entry: " + err.Error())
		}
	}

	for _, entry := range toAdd {
		s.xio.Info("Adding roster entry for " + entry.Jid)
		_, _, err := s.conn.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:   entry.Jid,
				Name:  entry.Name,
				Group: entry.Group,
			},
		})
		if err != nil {
			s.xio.Alert("Failed to add roster entry: " + err.Error())
		}
	}

	return true
}

func setEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

EachValue:
	for _, v := range a {
		for _, v2 := range b {
			if v == v2 {
				continue EachValue
			}
		}
		return false
	}

	return true
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

var newLine = []byte{'\n'}

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
	if _, err := r.out.Write(newLine); err != nil {
		return err
	}
	r.buf = r.buf[:0]
	return nil
}

type lineLogger struct {
	xio XIO
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

func printConversationInfo(s *Session, uid string, conversation *otr.Conversation) {
	fpr := conversation.TheirPublicKey.Fingerprint()
	fprUid := s.config.UserIdForFingerprint(fpr)
	s.xio.Info(fmt.Sprintf("  Fingerprint  for %s: %x", uid, fpr))
	s.xio.Info(fmt.Sprintf("  Session  ID  for %s: %x", uid, conversation.SSID))
	if fprUid == uid {
		s.xio.Info(fmt.Sprintf("  Identity key for %s is verified", uid))
	} else if len(fprUid) > 1 {
		s.xio.Alert(fmt.Sprintf("  Warning: %s is using an identity key which was verified for %s", uid, fprUid))
	} else if s.config.HasFingerprint(uid) {
		s.xio.Critical(fmt.Sprintf("  Identity key for %s is incorrect", uid))
	} else {
		s.xio.Alert(fmt.Sprintf("  Identity key for %s is not verified. You should use /otr-auth or /otr-authqa or /otr-authoob to verify their identity", uid))
	}
}

// promptForForm runs an XEP-0004 form and collects responses from the user.
func promptForForm(xio XIO, user, password, title, instructions string, fields []interface{}) error {
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
