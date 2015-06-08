package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"github.com/agl/xmpp-client/xmpp"
	"github.com/mattn/go-gtk/gtk"
	"golang.org/x/crypto/otr"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/html"
	"golang.org/x/net/proxy"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// GUI variables initialized so that the display() and
// buildGUI() functions don't create "undefined" errors
var window *gtk.Window
var statusTabView *gtk.TextView
var convoTabView *gtk.TextView
var contactsView *gtk.TextView

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

			// This is the "? after the error message for an unknown command.
			out = append(out, '?')
		} else {
			out = append(out, c)
		}
	}
	return out
}

func stripHTML(msg []byte) (out []byte) {
	z := html.NewTokenizer(bytes.NewReader(msg))

loop:
	for {
		tt := z.Next()
		switch tt {
		case html.TextToken:
			out = append(out, z.Text()...)
		case html.ErrorToken:
			if err := z.Err(); err != nil && err != io.EOF {
				out = msg
				return
			}
			break loop
		}
	}
	return
}

func terminalMessage(term *terminal.Terminal, color []byte, msg string, critical bool) {
	line := make([]byte, 0, len(msg)+16)
	line = append(line, ' ')
	line = append(line, color...)
	line = append(line, '*')
	line = append(line, term.Escape.Reset...)
	line = append(line, []byte(fmt.Sprintf(" (%s) ", time.Now().Format(time.Kitchen)))...)
	if critical {
		line = append(line, term.Escape.Red...)
	}
	line = appendTerminalEscaped(line, []byte(msg))
	if critical {
		line = append(line, term.Escape.Reset...)
	}
	line = append(line, '\n')
	term.Write(line)
}

func info(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Blue, msg, false)
}

func warn(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Magenta, msg, false)
}

func alert(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Red, msg, false)
}

func critical(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Red, msg, true)
}

type Session struct {
	account       string
	conn          *xmpp.Conn
	term          *terminal.Terminal
	statusTabView *gtk.TextView // added member
	convoTabView  *gtk.TextView // added member
	contactsView  *gtk.TextView // added member
	roster        []xmpp.RosterEntry
	input         Input
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

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, s.statusTabView, err.Error(), nil)
			}
			// -GUI

			alert(s.term, err.Error())
			return
		}
		stanzaChan <- stanza
	}
}

func updateTerminalSize(term *terminal.Terminal) {
	width, height, err := terminal.GetSize(0)
	if err != nil {
		return
	}
	term.SetSize(width, height)
}

func main() {

	// GTK GUI block
	if guiMode == 1 {
		initializeGTK()
		window, statusTabView, convoTabView, contactsView = buildGUI() // Assemble the GUI and get display vars
		window.ShowAll()                                               // Display the GTK window and its contents
	}
	// End GTK BLOCK -- call to gtk.Main() deferred until the end of main()

	flag.Parse()

	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err.Error())
	}
	defer terminal.Restore(0, oldState)
	term := terminal.NewTerminal(os.Stdin, "")
	updateTerminalSize(term)
	term.SetBracketedPasteMode(true)
	defer term.SetBracketedPasteMode(false)

	resizeChan := make(chan os.Signal)
	go func() {
		for _ = range resizeChan {
			updateTerminalSize(term)
		}
	}()
	signal.Notify(resizeChan, syscall.SIGWINCH)

	if len(*configFile) == 0 {
		homeDir := os.Getenv("HOME")
		if len(homeDir) == 0 {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "$HOME not set. Please either export $HOME or use the -config-file option.\n", nil)
			}
			// -GUI

			alert(term, "$HOME not set. Please either export $HOME or use the -config-file option.\n")
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

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, statusTabView, "Failed to parse config file: "+err.Error(), nil)
		}
		// -GUI

		alert(term, "Failed to parse config file: "+err.Error())
		config = new(Config)
		if !enroll(config, term) {
			return
		}
		config.filename = *configFile
		config.Save()
	}

	password := config.Password
	if len(password) == 0 {
		if password, err = term.ReadPassword(fmt.Sprintf("Password for %s (will not be saved to disk): ", config.Account)); err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "Failed to read password: "+err.Error(), nil)
			}
			// -GUI

			alert(term, "Failed to read password: "+err.Error())
			return
		}
	}
	term.SetPrompt("> ")

	parts := strings.SplitN(config.Account, "@", 2)
	if len(parts) != 2 {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, statusTabView, "Invalid username (want user@domain): "+err.Error(), nil)
		}
		// -GUI

		alert(term, "Invalid username (want user@domain): "+config.Account)
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

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "Cannot connect via a proxy without Server and Port being set in the config file as an SRV lookup would leak information.", nil)
			}
			// -GUI

			alert(term, "Cannot connect via a proxy without Server and Port being set in the config file as an SRV lookup would leak information.")
			return
		}
		host, port, err := xmpp.Resolve(domain)
		if err != nil {
			alert(term, "Failed to resolve XMPP server: "+err.Error())
			return
		}
		addr = fmt.Sprintf("%s:%d", host, port)
	}

	var dialer proxy.Dialer
	for i := len(config.Proxies) - 1; i >= 0; i-- {
		u, err := url.Parse(config.Proxies[i])
		if err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "Failed to parse "+config.Proxies[i]+" as a URL: "+err.Error(), nil)
			}
			// -GUI

			alert(term, "Failed to parse "+config.Proxies[i]+" as a URL: "+err.Error())
			return
		}
		if dialer == nil {
			dialer = proxy.Direct
		}
		if dialer, err = proxy.FromURL(u, dialer); err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "Failed to parse "+config.Proxies[i]+" as a proxy: "+err.Error(), nil)
			}
			// -GUI

			alert(term, "Failed to parse "+config.Proxies[i]+" as a proxy: "+err.Error())
			return
		}
	}

	var certSHA256 []byte
	if len(config.ServerCertificateSHA256) > 0 {
		certSHA256, err = hex.DecodeString(config.ServerCertificateSHA256)
		if err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "Failed to parse ServerCertificateSHA256 (should be hex string): "+err.Error(), nil)
			}
			// -GUI

			alert(term, "Failed to parse ServerCertificateSHA256 (should be hex string): "+err.Error())
			return
		}
		if len(certSHA256) != 32 {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "ServerCertificateSHA256 is not 32 bytes long", nil)
			}
			// -GUI

			alert(term, "ServerCertificateSHA256 is not 32 bytes long")
			return
		}
	}

	var createCallback xmpp.FormCallback
	if *createAccount {
		createCallback = func(title, instructions string, fields []interface{}) error {
			return promptForForm(term, user, password, title, instructions, fields)
		}
	}

	xmppConfig := &xmpp.Config{
		Log:                     &lineLogger{term, nil},
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
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
		},
	}

	if len(config.RawLogFile) > 0 {
		rawLog, err := os.OpenFile(config.RawLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "Failed to open raw log file: "+err.Error(), nil)
			}
			// -GUI

			alert(term, "Failed to open raw log file: "+err.Error())
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

		// +GUI
		if guiMode == 1 {
			g.display(INFO, statusTabView, "Making connection to "+addr+" via proxy", nil)
		}
		// -GUI

		info(term, "Making connection to "+addr+" via proxy")

		if xmppConfig.Conn, err = dialer.Dial("tcp", addr); err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, statusTabView, "Failed to connect via proxy: "+err.Error(), nil)
			}
			// -GUI

			alert(term, "Failed to connect via proxy: "+err.Error())
			return
		}
	}

	conn, err := xmpp.Dial(addr, user, domain, password, xmppConfig)
	if err != nil {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, statusTabView, "Failed to connect to XMPP server: "+err.Error(), nil)
		}
		// -GUI

		alert(term, "Failed to connect to XMPP server: "+err.Error())
		return
	}

	s := Session{
		account:           config.Account,
		conn:              conn,
		term:              term,
		statusTabView:     statusTabView, // GUI -- added member
		convoTabView:      convoTabView,  // GUI -- added member
		contactsView:      contactsView,  // GUI -- added member
		conversations:     make(map[string]*otr.Conversation),
		knownStates:       make(map[string]string),
		privateKey:        new(otr.PrivateKey),
		config:            config,
		pendingRosterChan: make(chan *rosterEdit),
		pendingSubscribes: make(map[string]string),
		lastActionTime:    time.Now(),
	}

	// +GUI
	if guiMode == 1 {
		g.display(INFO, statusTabView, "Fetching roster", nil)
	}
	// -GUI

	info(term, "Fetching roster")

	//var rosterReply chan xmpp.Stanza
	rosterReply, _, err := s.conn.RequestRoster()
	if err != nil {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, statusTabView, "Failed to request roster: "+err.Error(), nil)
		}
		// -GUI

		alert(term, "Failed to request roster: "+err.Error())
		return
	}

	conn.SignalPresence("")

	s.input = Input{
		term:        term,
		uidComplete: new(priorityList),
	}

	// This is the channel that receives commands from input.
	commandChan := make(chan interface{})

	// Modified for GUI mode check
	if guiMode == 1 {
		go s.input.GuiProcessCommands(commandChan)
	} else {
		go s.input.ProcessCommands(commandChan)
	}

	// This is the channel that receives incoming messages.
	stanzaChan := make(chan xmpp.Stanza)
	go s.readMessages(stanzaChan)

	s.privateKey.Parse(config.PrivateKey)
	s.timeouts = make(map[xmpp.Cookie]time.Time)

	// +GUI -- Some formatting irregularities on this one, solved.
	if guiMode == 1 {
		key := fmt.Sprintf("Your fingerprint is %x", s.privateKey.Fingerprint())
		g.display(INFO, statusTabView, key, nil)
	}
	// -GUI

	info(term, fmt.Sprintf("Your fingerprint is %x", s.privateKey.Fingerprint()))

	ticker := time.NewTicker(1 * time.Second)

	// MainLoop: Converted to a goroutine so it can run concurrently with the GUI
	// This will need to be reverted and wrapped in a conditional once the
	// GUI and CLI versions are separated completely.

	//		if guiMode == 1 {
	//			MainLoop:
	//		} else {
	//			go func() {
	//		}

	if guiMode == 0 {
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
					info(s.term, "Please edit "+edit.fileName+" and run /rostereditdone when complete")
					s.pendingRosterEdit = edit
					continue
				}
				if s.processEditedRoster(edit) {
					s.pendingRosterEdit = nil
				} else {
					alert(s.term, "Please reedit file and run /rostereditdone again")
				}

			case rosterStanza, ok := <-rosterReply:
				if !ok {
					alert(s.term, "Failed to read roster: "+err.Error())
					return
				}
				if s.roster, err = xmpp.ParseRoster(rosterStanza); err != nil {
					alert(s.term, "Failed to parse roster: "+err.Error())
					return
				}
				for _, entry := range s.roster {
					s.input.AddUser(entry.Jid)
				}
				info(s.term, "Roster received")

			// Here is where commands, including msgCommand, are directed.

			case cmd, ok := <-commandChan:
				if !ok {
					warn(term, "Exiting because command channel closed")
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
						alert(s.term, "Error sending version request: "+err.Error())
						continue
					}
					s.timeouts[cookie] = time.Now().Add(5 * time.Second)
					go s.awaitVersionReply(replyChan, cmd.User)
				case rosterCommand:
					info(s.term, "Current roster:")
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
						info(s.term, line)
					}
				case rosterEditCommand:
					if s.pendingRosterEdit != nil {
						warn(s.term, "Aborting previous roster edit")
						s.pendingRosterEdit = nil
					}
					rosterCopy := make([]xmpp.RosterEntry, len(s.roster))
					copy(rosterCopy, s.roster)
					go s.editRoster(rosterCopy)
				case rosterEditDoneCommand:
					if s.pendingRosterEdit == nil {
						warn(s.term, "No roster edit in progress. Use /rosteredit to start one")
						continue
					}
					go s.loadEditedRoster(*s.pendingRosterEdit)
				case toggleStatusUpdatesCommand:
					s.config.HideStatusUpdates = !s.config.HideStatusUpdates
					s.config.Save()
					// Tell the user the current state of the statuses
					if s.config.HideStatusUpdates {
						info(s.term, "Status updates disabled")
					} else {
						info(s.term, "Status updates enabled")
					}
				case confirmCommand:
					s.handleConfirmOrDeny(cmd.User, true /* confirm */)
				case denyCommand:
					s.handleConfirmOrDeny(cmd.User, false /* deny */)
				case addCommand:
					s.conn.SendPresence(cmd.User, "subscribe", "" /* generate id */)

				// OUTGOING MESSAGES

				case msgCommand:
					conversation, ok := s.conversations[cmd.to]
					isEncrypted := ok && conversation.IsEncrypted()
					if cmd.setPromptIsEncrypted != nil {
						cmd.setPromptIsEncrypted <- isEncrypted
					}
					if !isEncrypted && config.ShouldEncryptTo(cmd.to) {
						warn(s.term, fmt.Sprintf("Did not send: no encryption established with %s", cmd.to))
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
							alert(s.term, err.Error())
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
					info(term, fmt.Sprintf("Your OTR fingerprint is %x", s.privateKey.Fingerprint()))
					for to, conversation := range s.conversations {
						if conversation.IsEncrypted() {
							info(s.term, fmt.Sprintf("Secure session with %s underway:", to))
							printConversationInfo(&s, to, conversation)
						}
					}
				case endOTRCommand:
					to := string(cmd.User)
					conversation, ok := s.conversations[to]
					if !ok {
						alert(s.term, "No secure session established")
						break
					}
					msgs := conversation.End()
					for _, msg := range msgs {
						s.conn.Send(to, string(msg))
					}
					s.input.SetPromptForTarget(cmd.User, false)
					warn(s.term, "OTR conversation ended with "+cmd.User)
				case authQACommand:
					to := string(cmd.User)
					conversation, ok := s.conversations[to]
					if !ok {
						alert(s.term, "Can't authenticate without a secure conversation established")
						break
					}
					msgs, err := conversation.Authenticate(cmd.Question, []byte(cmd.Secret))
					if err != nil {
						alert(s.term, "Error while starting authentication with "+to+": "+err.Error())
					}
					for _, msg := range msgs {
						s.conn.Send(to, string(msg))
					}
				case authOobCommand:
					fpr, err := hex.DecodeString(cmd.Fingerprint)
					if err != nil {
						alert(s.term, fmt.Sprintf("Invalid fingerprint %s - not authenticated", cmd.Fingerprint))
						break
					}
					existing := s.config.UserIdForFingerprint(fpr)
					if len(existing) != 0 {
						alert(s.term, fmt.Sprintf("Fingerprint %s already belongs to %s", cmd.Fingerprint, existing))
						break
					}
					s.config.KnownFingerprints = append(s.config.KnownFingerprints, KnownFingerprint{fingerprint: fpr, UserId: cmd.User})
					s.config.Save()
					info(s.term, fmt.Sprintf("Saved manually verified fingerprint %s for %s", cmd.Fingerprint, cmd.User))
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
				}
			case rawStanza, ok := <-stanzaChan:
				if !ok {
					warn(term, "Exiting because channel to server closed")
					break MainLoop
				}
				switch stanza := rawStanza.Value.(type) {

				// This case is an incoming IM
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
						alert(term, "Failed to send IQ message: "+err.Error())
					}
				case *xmpp.StreamError:
					var text string
					if len(stanza.Text) > 0 {
						text = stanza.Text
					} else {
						text = fmt.Sprintf("%s", stanza.Any)
					}
					alert(term, "Exiting in response to fatal error from server: "+text)
					break MainLoop

				default:
					info(term, fmt.Sprintf("%s %s", rawStanza.Name, rawStanza.Value))
				}
			}
		}

		//
		// GUI version of MainLoop (a Go-routine)
		//

	} else {
		go func() {
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

						g.display(INFO, statusTabView, "Please edit "+edit.fileName+" and run /rostereditdone when complete", nil)

						s.pendingRosterEdit = edit
						continue
					}
					if s.processEditedRoster(edit) {
						s.pendingRosterEdit = nil
					} else {
						g.display(ALERT, statusTabView, "Please reedit file and run /rostereditdone again", nil)
					}

				case rosterStanza, ok := <-rosterReply:
					if !ok {
						g.display(ALERT, statusTabView, "Failed to read roster: "+err.Error(), nil)
						return
					}
					if s.roster, err = xmpp.ParseRoster(rosterStanza); err != nil {
						g.display(ALERT, statusTabView, "Failed to parse roster: "+err.Error(), nil)
						return
					}
					for _, entry := range s.roster {
						s.input.AddUser(entry.Jid)
					}
					g.display(INFO, statusTabView, "Roster received", nil)

				// Here is where commands, including msgCommand, are directed.

				case cmd, ok := <-commandChan:
					if !ok {
						g.display(WARN, statusTabView, "Exiting because command channel closed", nil)
						break // MainLoop
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
						break // MainLoop

					case versionCommand:
						replyChan, cookie, err := s.conn.SendIQ(cmd.User, "get", xmpp.VersionQuery{})
						if err != nil {
							g.display(ALERT, statusTabView, "Error sending version request: "+err.Error(), nil)
							continue
						}
						s.timeouts[cookie] = time.Now().Add(5 * time.Second)
						go s.awaitVersionReply(replyChan, cmd.User)

					//
					// rosterCommand picks up the /roster and /roster --online commands
					// This command is disabled in the GUI version and the code is moved
					// to the event-driven guiProcessPresence() method. To Do: Add a GUI
					// toggle to choose --online or not.

					//					case rosterCommand:

					//						maxLen := 0
					//						for _, item := range s.roster {
					//							if maxLen < len(item.Jid) {
					//								maxLen = len(item.Jid)
					//							}
					//						}
					//						g.clear(s.contactsView) // clean up Contacts window before posting update

					//						for _, item := range s.roster {
					//							state, ok := s.knownStates[item.Jid]

					//							line := ""
					//							if ok {
					//								line += "[*] "
					//							} else if cmd.OnlineOnly {
					//								continue
					//							} else {
					//								line += "[ ] "
					//							}

					//							line += item.Jid
					//							numSpaces := 1 + (maxLen - len(item.Jid))
					//							for i := 0; i < numSpaces; i++ {
					//								line += " "
					//							}
					//							line += item.Subscription + "\t" + item.Name
					//							if ok {
					//								line += "\t" + state
					//							}
					//							g.display(ROSTER, s.contactsView, line, nil)
					//						}

					case rosterEditCommand:
						if s.pendingRosterEdit != nil {
							g.display(WARN, s.statusTabView, "Aborting previous roster edit", nil)
							s.pendingRosterEdit = nil
						}
						rosterCopy := make([]xmpp.RosterEntry, len(s.roster))
						copy(rosterCopy, s.roster)
						go s.editRoster(rosterCopy)
					case rosterEditDoneCommand:
						if s.pendingRosterEdit == nil {
							g.display(WARN, s.statusTabView, "No roster edit in progress. Use /rosteredit to start one", nil)
							continue
						}
						go s.loadEditedRoster(*s.pendingRosterEdit)
					case toggleStatusUpdatesCommand:
						s.config.HideStatusUpdates = !s.config.HideStatusUpdates
						s.config.Save()
						// Tell the user the current state of the statuses
						if s.config.HideStatusUpdates {
							g.display(INFO, s.statusTabView, "Status updates disabled", nil)
						} else {
							g.display(INFO, s.statusTabView, "Status updates enabled", nil)
						}
					case confirmCommand:
						s.handleConfirmOrDeny(cmd.User, true /* confirm */)
					case denyCommand:
						s.handleConfirmOrDeny(cmd.User, false /* deny */)
					case addCommand:
						s.conn.SendPresence(cmd.User, "subscribe", "" /* generate id */)

					// OUTGOING MESSAGES

					case msgCommand:
						conversation, ok := s.conversations[cmd.to]
						isEncrypted := ok && conversation.IsEncrypted()
						if cmd.setPromptIsEncrypted != nil {
							cmd.setPromptIsEncrypted <- isEncrypted
						}
						if !isEncrypted && config.ShouldEncryptTo(cmd.to) {
							g.display(WARN, s.statusTabView, fmt.Sprintf("Did not send: no encryption established with %s", cmd.to), nil)
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
						g.display(INFO, s.statusTabView, fmt.Sprintf("Your OTR fingerprint is %x", s.privateKey.Fingerprint()), nil)
						for to, conversation := range s.conversations {
							if conversation.IsEncrypted() {
								g.display(INFO, s.statusTabView, fmt.Sprintf("Secure session with %s underway:", to), nil)
								printConversationInfo(&s, to, conversation)
							}
						}
					case endOTRCommand:
						to := string(cmd.User)
						conversation, ok := s.conversations[to]
						if !ok {
							g.display(ALERT, s.statusTabView, "Error sending version request: "+err.Error(), nil)
							break
						}
						msgs := conversation.End()
						for _, msg := range msgs {
							s.conn.Send(to, string(msg))
						}
						s.input.SetPromptForTarget(cmd.User, false)
						g.display(WARN, s.statusTabView, "OTR conversation ended with "+cmd.User, nil)
					case authQACommand:
						to := string(cmd.User)
						conversation, ok := s.conversations[to]
						if !ok {
							g.display(ALERT, s.statusTabView, "Can't authenticate without a secure conversation established", nil)
							break
						}
						msgs, err := conversation.Authenticate(cmd.Question, []byte(cmd.Secret))
						if err != nil {
							g.display(ALERT, s.statusTabView, "Error while starting authentication with "+to+": "+err.Error(), nil)
						}
						for _, msg := range msgs {
							s.conn.Send(to, string(msg))
						}
					case authOobCommand:
						fpr, err := hex.DecodeString(cmd.Fingerprint)
						if err != nil {
							g.display(ALERT, s.statusTabView, fmt.Sprintf("Invalid fingerprint %s - not authenticated", cmd.Fingerprint), nil)
							break
						}
						existing := s.config.UserIdForFingerprint(fpr)
						if len(existing) != 0 {
							g.display(ALERT, s.statusTabView, fmt.Sprintf("Fingerprint %s already belongs to %s", cmd.Fingerprint, existing), nil)
							break
						}
						s.config.KnownFingerprints = append(s.config.KnownFingerprints, KnownFingerprint{fingerprint: fpr, UserId: cmd.User})
						s.config.Save()
						g.display(INFO, s.statusTabView, fmt.Sprintf("Saved manually verified fingerprint %s for %s", cmd.Fingerprint, cmd.User), nil)
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
					}
				case rawStanza, ok := <-stanzaChan:
					if !ok {
						g.display(WARN, statusTabView, "Exiting because channel to server closed", nil)
						break // MainLoop
					}
					switch stanza := rawStanza.Value.(type) {

					// This case is an incoming IM
					case *xmpp.ClientMessage:
						s.processClientMessage(stanza)

					case *xmpp.ClientPresence:
						s.guiProcessPresence(stanza)

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
							g.display(ALERT, statusTabView, "Failed to send IQ message: "+err.Error(), nil)
						}
					case *xmpp.StreamError:
						var text string
						if len(stanza.Text) > 0 {
							text = stanza.Text
						} else {
							text = fmt.Sprintf("%s", stanza.Any)
						}
						g.display(ALERT, statusTabView, "Exiting in response to fatal error from server: "+text, nil)
						break // MainLoop

					default:
						g.display(INFO, statusTabView, fmt.Sprintf("%s %s", rawStanza.Name, rawStanza.Value), nil)
					}
				}
			}
		}() // end of go-routinized MainLoop
	}

	if guiMode == 1 {
		gtk.Main()
	} else {
		os.Stdout.Write([]byte("\n"))
	}
} // end of main()

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

			// +GUI
			if guiMode == 1 {
				g.display(WARN, s.statusTabView, "Ignoring roster IQ from bad address: "+stanza.From, nil)
			}
			// -GUI

			warn(s.term, "Ignoring roster IQ from bad address: "+stanza.From)
			return nil
		}
		var roster xmpp.Roster
		if err := xml.NewDecoder(bytes.NewBuffer(stanza.Query)).Decode(&roster); err != nil || len(roster.Item) == 0 {

			// +GUI
			if guiMode == 1 {
				g.display(WARN, s.statusTabView, "Failed to parse roster push IQ", nil)
			}
			// -GUI

			warn(s.term, "Failed to parse roster push IQ")
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

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, "Unknown IQ: "+startElem.Name.Space+" "+startElem.Name.Local, nil)
		}
		// -GUI

		info(s.term, "Unknown IQ: "+startElem.Name.Space+" "+startElem.Name.Local)
	}

	return nil
}

func (s *Session) handleConfirmOrDeny(jid string, isConfirm bool) {
	id, ok := s.pendingSubscribes[jid]
	if !ok {

		// +GUI
		if guiMode == 1 {
			g.display(WARN, s.statusTabView, "No pending subscription from "+jid, nil)
		}
		// -GUI

		warn(s.term, "No pending subscription from "+jid)
		return
	}
	delete(s.pendingSubscribes, id)
	typ := "unsubscribed"
	if isConfirm {
		typ = "subscribed"
	}
	if err := s.conn.SendPresence(jid, typ, id); err != nil {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, "Error sending presence stanza: "+err.Error(), nil)
		}
		// -GUI

		alert(s.term, "Error sending presence stanza: "+err.Error())
	}
}

func (s *Session) processClientMessage(stanza *xmpp.ClientMessage) {
	from := xmpp.RemoveResourceFromJid(stanza.From)

	if stanza.Type == "error" {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, "Error reported from "+from+": "+stanza.Body, nil)
		}
		// -GUI

		alert(s.term, "Error reported from "+from+": "+stanza.Body)
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

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, "While processing message from "+from+": "+err.Error(), nil)
		}
		// -GUI

		alert(s.term, "While processing message from "+from+": "+err.Error())
		s.conn.Send(stanza.From, otr.ErrorPrefix+"Error processing message")
	}
	for _, msg := range toSend {
		s.conn.Send(stanza.From, string(msg))
	}

	switch change {
	case otr.NewKeys:
		s.input.SetPromptForTarget(from, true)

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, fmt.Sprintf("New OTR session with %s established", from), nil)
		}
		// -GUI

		info(s.term, fmt.Sprintf("New OTR session with %s established", from))
		printConversationInfo(s, from, conversation) // key sig and validation status
	case otr.ConversationEnded:
		s.input.SetPromptForTarget(from, false)
		// This is probably unsafe without a policy that _forces_ crypto to
		// _everyone_ by default and refuses plaintext. Users might not notice
		// their buddy has ended a session, which they have also ended, and they
		// might send a plain text message. So we should ensure they _want_ this
		// feature and have set it as an explicit preference.
		if s.config.OTRAutoTearDown {
			if s.conversations[from] == nil {

				// +GUI
				if guiMode == 1 {
					g.display(ALERT, s.statusTabView, fmt.Sprintf("No secure session established; unable to automatically tear down OTR conversation with %s.", from), nil)
				}
				// -GUI

				alert(s.term, fmt.Sprintf("No secure session established; unable to automatically tear down OTR conversation with %s.", from))
				break
			} else {

				// +GUI
				if guiMode == 1 {
					g.display(INFO, s.statusTabView, fmt.Sprintf("%s has ended the secure conversation.", from), nil)
				}
				// -GUI

				info(s.term, fmt.Sprintf("%s has ended the secure conversation.", from))
				msgs := conversation.End()
				for _, msg := range msgs {
					s.conn.Send(from, string(msg))
				}

				// +GUI
				if guiMode == 1 {
					g.display(INFO, s.statusTabView, fmt.Sprintf("Secure session with %s has been automatically ended. Messages will be sent in the clear until another OTR session is established.", from), nil)
				}
				// -GUI

				info(s.term, fmt.Sprintf("Secure session with %s has been automatically ended. Messages will be sent in the clear until another OTR session is established.", from))
			}
		} else {

			// +GUI
			if guiMode == 1 {
				g.display(INFO, s.statusTabView, fmt.Sprintf("%s has ended the secure conversation. You should do likewise with /otr-end %s", from, from), nil)
			}
			// -GUI

			info(s.term, fmt.Sprintf("%s has ended the secure conversation. You should do likewise with /otr-end %s", from, from))
		}
	case otr.SMPSecretNeeded:

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, fmt.Sprintf("%s is attempting to authenticate. Please supply mutual shared secret with /otr-auth user secret", from), nil)
		}
		// -GUI

		info(s.term, fmt.Sprintf("%s is attempting to authenticate. Please supply mutual shared secret with /otr-auth user secret", from))
		if question := conversation.SMPQuestion(); len(question) > 0 {

			// +GUI
			if guiMode == 1 {
				g.display(INFO, s.statusTabView, fmt.Sprintf("%s asks: %s", from, question), nil)
			}
			// -GUI

			info(s.term, fmt.Sprintf("%s asks: %s", from, question))
		}
	case otr.SMPComplete:

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, fmt.Sprintf("Authentication with %s successful", from), nil)
		}
		// -GUI

		info(s.term, fmt.Sprintf("Authentication with %s successful", from))
		fpr := conversation.TheirPublicKey.Fingerprint()
		if len(s.config.UserIdForFingerprint(fpr)) == 0 {
			s.config.KnownFingerprints = append(s.config.KnownFingerprints, KnownFingerprint{fingerprint: fpr, UserId: from})
		}
		s.config.Save()
	case otr.SMPFailed:

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, fmt.Sprintf("Authentication with %s failed", from), nil)
		}
		// -GUI

		alert(s.term, fmt.Sprintf("Authentication with %s failed", from))
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

				// +GUI
				if guiMode == 1 {
					g.display(INFO, s.statusTabView, fmt.Sprintf("%s appears to support OTRv1. You should encourage them to upgrade their OTR client!", from), nil)
				}
				// -GUI

				info(s.term, fmt.Sprintf("%s appears to support OTRv1. You should encourage them to upgrade their OTR client!", from))
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

	if s.config.OTRAutoStartSession && detectedOTRVersion >= 2 {

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, fmt.Sprintf("%s appears to support OTRv%d. We are attempting to start an OTR session with them.", from, detectedOTRVersion), nil)
		}
		// -GUI

		info(s.term, fmt.Sprintf("%s appears to support OTRv%d. We are attempting to start an OTR session with them.", from, detectedOTRVersion))
		s.conn.Send(from, otr.QueryMessage)
	} else if s.config.OTRAutoStartSession && detectedOTRVersion == 1 {

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, fmt.Sprintf("%s appears to support OTRv%d. You should encourage them to upgrade their OTR client!", from, detectedOTRVersion), nil)
		}
		// -GUI

		info(s.term, fmt.Sprintf("%s appears to support OTRv%d. You should encourage them to upgrade their OTR client!", from, detectedOTRVersion))
	}

	var line []byte

	if guiMode == 0 {
		if encrypted {
			line = append(line, s.term.Escape.Green...) // removed for GUI
		} else {
			line = append(line, s.term.Escape.Red...)
		}
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

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, s.statusTabView, fmt.Sprintf("Can not parse Delayed Delivery timestamp, using quoted string instead."), nil)
			}
			// -GUI

			alert(s.term, "Can not parse Delayed Delivery timestamp, using quoted string instead.")
			timestamp = fmt.Sprintf("%q", stanza.Delay.Stamp)
		}
	} else {
		messageTime = time.Now()
	}
	if len(timestamp) == 0 {
		timestamp = messageTime.Format(time.Stamp)
	}

	t := fmt.Sprintf("(%s) %s: ", timestamp, from)
	line = append(line, []byte(t)...)

	if guiMode == 0 {
		line = append(line, s.term.Escape.Reset...) // removed for GUI
	}

	line = appendTerminalEscaped(line, stripHTML(out))
	line = append(line, '\n') // inserts a blank line after incoming message

	if guiMode == 0 {
		if s.config.Bell {
			line = append(line, '\a')
		}
	}

	//
	// Here is the GUI output for incoming messages.
	//

	// +GUI
	if guiMode == 1 {
		g.display(MSG_INCOMING, s.convoTabView, string(line), nil)
	}
	// -GUI

	s.term.Write(line)
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

			// +GUI
			if guiMode == 1 {
				g.display(INFO, s.statusTabView, "Failed to run notify command: "+err.Error(), nil)
			}
			// -GUI

			alert(s.term, "Failed to run notify command: "+err.Error())
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
		info(s.term, jid+" wishes to see when you're online. Use '/confirm "+jid+"' to confirm (or likewise with /deny to decline)")
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
		var line []byte
		line = append(line, []byte(fmt.Sprintf("   (%s) ", time.Now().Format(time.Kitchen)))...)
		line = append(line, s.term.Escape.Magenta...)
		line = append(line, []byte(from)...)
		line = append(line, ':')
		line = append(line, s.term.Escape.Reset...)
		line = append(line, ' ')
		if gone {
			line = append(line, []byte("offline")...)
		} else if len(stanza.Show) > 0 {
			line = append(line, []byte(stanza.Show)...)
		} else {
			line = append(line, []byte("online")...)
		}
		line = append(line, ' ')
		line = append(line, []byte(stanza.Status)...)
		line = append(line, '\n')

		s.term.Write(line)
	}
}

func (s *Session) awaitVersionReply(ch <-chan xmpp.Stanza, user string) {
	stanza, ok := <-ch
	if !ok {

		// +GUI
		if guiMode == 1 {
			g.display(WARN, s.statusTabView, "Version request to "+user+" timed out", nil)
		}
		// -GUI

		warn(s.term, "Version request to "+user+" timed out")
		return
	}
	reply, ok := stanza.Value.(*xmpp.ClientIQ)
	if !ok {

		// +GUI
		if guiMode == 1 {
			g.display(WARN, s.statusTabView, "Version request to "+user+" resulted in bad reply type", nil)
		}
		// -GUI

		warn(s.term, "Version request to "+user+" resulted in bad reply type")
		return
	}

	if reply.Type == "error" {

		// +GUI
		if guiMode == 1 {
			g.display(WARN, s.statusTabView, "Version request to "+user+" resulted in XMPP error", nil)
		}
		// -GUI

		warn(s.term, "Version request to "+user+" resulted in XMPP error")
		return
	} else if reply.Type != "result" {

		// +GUI
		if guiMode == 1 {
			g.display(WARN, s.statusTabView, "Version request to "+user+" resulted in response with unknown type: "+reply.Type, nil)
		}
		// -GUI

		warn(s.term, "Version request to "+user+" resulted in response with unknown type: "+reply.Type)
		return
	}

	buf := bytes.NewBuffer(reply.Query)
	var versionReply xmpp.VersionReply
	if err := xml.NewDecoder(buf).Decode(&versionReply); err != nil {

		// +GUI
		if guiMode == 1 {
			g.display(WARN, s.statusTabView, "Failed to parse version reply from "+user+": "+err.Error(), nil)
		}
		// -GUI

		warn(s.term, "Failed to parse version reply from "+user+": "+err.Error())
		return
	}

	// +GUI
	if guiMode == 1 {
		g.display(INFO, s.statusTabView, fmt.Sprintf("Version reply from %s: %#v", user, versionReply), nil)
	}
	// -GUI

	info(s.term, fmt.Sprintf("Version reply from %s: %#v", user, versionReply))
}

// editRoster runs in a goroutine and writes the roster to a file that the user
// can edit.
func (s *Session) editRoster(roster []xmpp.RosterEntry) {
	// In case the editor rewrites the file, we work inside a temp
	// directory.
	dir, err := ioutil.TempDir("" /* system default temp dir */, "xmpp-client")
	if err != nil {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, "Failed to create temp dir to edit roster: "+err.Error(), nil)
		}
		// -GUI

		alert(s.term, "Failed to create temp dir to edit roster: "+err.Error())
		return
	}

	mode, err := os.Stat(dir)
	if err != nil || mode.Mode()&os.ModePerm != 0700 {
		panic("broken system libraries gave us an insecure temp dir")
	}

	fileName := filepath.Join(dir, "roster")
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, "Failed to create temp file: "+err.Error(), nil)
		}
		// -GUI

		alert(s.term, "Failed to create temp file: "+err.Error())
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
		escapedJids[i] = escapeNonASCII(item.Jid)
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
			line += "name:" + escapeNonASCII(item.Name)
			if len(item.Group) > 0 {
				line += "\t"
			}
		}

		for j, group := range item.Group {
			if j > 0 {
				line += "\t"
			}
			line += "group:" + escapeNonASCII(group)
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

var hexTable = "0123456789abcdef"

// escapeNonASCII replaces tabs and other non-printable characters with a
// "\x01" form of hex escaping. It works on a byte-by-byte basis.
func escapeNonASCII(in string) string {
	escapes := 0
	for i := 0; i < len(in); i++ {
		if in[i] < 32 || in[i] > 126 || in[i] == '\\' {
			escapes++
		}
	}

	if escapes == 0 {
		return in
	}

	out := make([]byte, 0, len(in)+3*escapes)
	for i := 0; i < len(in); i++ {
		if in[i] < 32 || in[i] > 126 || in[i] == '\\' {
			out = append(out, '\\', 'x', hexTable[in[i]>>4], hexTable[in[i]&15])
		} else {
			out = append(out, in[i])
		}
	}

	return string(out)
}

// unescapeNonASCII undoes the transformation of escapeNonASCII.
func unescapeNonASCII(in string) (string, error) {
	needsUnescaping := false
	for i := 0; i < len(in); i++ {
		if in[i] == '\\' {
			needsUnescaping = true
			break
		}
	}

	if !needsUnescaping {
		return in, nil
	}

	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == '\\' {
			if len(in) <= i+3 {
				return "", errors.New("truncated escape sequence at end: " + in)
			}
			if in[i+1] != 'x' {
				return "", errors.New("escape sequence didn't start with \\x in: " + in)
			}
			v, err := strconv.ParseUint(in[i+2:i+4], 16, 8)
			if err != nil {
				return "", errors.New("failed to parse value in '" + in + "': " + err.Error())
			}
			out = append(out, byte(v))
			i += 3
		} else {
			out = append(out, in[i])
		}
	}

	return string(out), nil
}

func (s *Session) loadEditedRoster(edit rosterEdit) {
	contents, err := ioutil.ReadFile(edit.fileName)
	if err != nil {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, "Failed to load edited roster: "+err.Error(), nil)
		}
		// -GUI

		alert(s.term, "Failed to load edited roster: "+err.Error())
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

		if entry.Jid, err = unescapeNonASCII(string(string(parts[0]))); err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, s.statusTabView, fmt.Sprintf("Failed to parse JID on line %d: %s", i+1, err), nil)
			}
			// -GUI

			alert(s.term, fmt.Sprintf("Failed to parse JID on line %d: %s", i+1, err))
			return false
		}
		for _, part := range parts[1:] {
			if len(part) == 0 {
				continue
			}

			pos := bytes.IndexByte(part, ':')
			if pos == -1 {

				// +GUI
				if guiMode == 1 {
					g.display(ALERT, s.statusTabView, fmt.Sprintf("Failed to find colon in item on line %d", i+1), nil)
				}
				// -GUI

				alert(s.term, fmt.Sprintf("Failed to find colon in item on line %d", i+1))
				return false
			}

			typ := string(part[:pos])
			value, err := unescapeNonASCII(string(part[pos+1:]))
			if err != nil {

				// +GUI
				if guiMode == 1 {
					g.display(ALERT, s.statusTabView, fmt.Sprintf("Failed to unescape item on line %d: %s", i+1, err), nil)
				}
				// -GUI

				alert(s.term, fmt.Sprintf("Failed to unescape item on line %d: %s", i+1, err))
				return false
			}

			switch typ {
			case "name":
				if len(entry.Name) > 0 {

					// +GUI
					if guiMode == 1 {
						g.display(ALERT, s.statusTabView, fmt.Sprintf("Multiple names given for contact on line %d", i+1), nil)
					}
					// -GUI

					alert(s.term, fmt.Sprintf("Multiple names given for contact on line %d", i+1))
					return false
				}
				entry.Name = value
			case "group":
				if len(value) > 0 {
					entry.Group = append(entry.Group, value)
				}
			default:

				// +GUI
				if guiMode == 1 {
					g.display(ALERT, s.statusTabView, fmt.Sprintf("Unknown item tag '%s' on line %d", typ, i+1), nil)
				}
				// -GUI

				alert(s.term, fmt.Sprintf("Unknown item tag '%s' on line %d", typ, i+1))
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

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, "Deleting roster entry for "+jid, nil)
		}
		// -GUI

		info(s.term, "Deleting roster entry for "+jid)
		_, _, err := s.conn.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:          jid,
				Subscription: "remove",
			},
		})
		if err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, s.statusTabView, "Failed to remove roster entry: "+err.Error(), nil)
			}
			// -GUI

			alert(s.term, "Failed to remove roster entry: "+err.Error())
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

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, "Updating roster entry for "+entry.Jid, nil)
		}
		// -GUI

		info(s.term, "Updating roster entry for "+entry.Jid)
		_, _, err := s.conn.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:   entry.Jid,
				Name:  entry.Name,
				Group: entry.Group,
			},
		})
		if err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, s.statusTabView, "Failed to update roster entry: "+err.Error(), nil)
			}
			// -GUI

			alert(s.term, "Failed to update roster entry: "+err.Error())
		}
	}

	for _, entry := range toAdd {

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, "Adding roster entry for "+entry.Jid, nil)
		}
		// -GUI

		info(s.term, "Adding roster entry for "+entry.Jid)
		_, _, err := s.conn.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:   entry.Jid,
				Name:  entry.Name,
				Group: entry.Group,
			},
		})
		if err != nil {

			// +GUI
			if guiMode == 1 {
				g.display(ALERT, s.statusTabView, "Failed to add roster entry: "+err.Error(), nil)
			}
			// -GUI

			alert(s.term, "Failed to add roster entry: "+err.Error())
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
	term *terminal.Terminal
	buf  []byte
}

func (l *lineLogger) logLines(in []byte) []byte {
	for len(in) > 0 {
		if newLine := bytes.IndexByte(in, '\n'); newLine >= 0 {

			// +GUI -- DOESN'T WORK
			// -GUI

			info(l.term, string(in[:newLine]))
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

	// +GUI
	if guiMode == 1 {
		g.display(INFO, s.statusTabView, fmt.Sprintf("  Fingerprint  for %s: %x", uid, fpr), nil)
	}
	// -GUI

	info(s.term, fmt.Sprintf("  Fingerprint  for %s: %x", uid, fpr))

	// +GUI
	if guiMode == 1 {
		g.display(INFO, s.statusTabView, fmt.Sprintf("  Session  ID  for %s: %x", uid, conversation.SSID), nil)
	}
	// -GUI

	info(s.term, fmt.Sprintf("  Session  ID  for %s: %x", uid, conversation.SSID))
	if fprUid == uid {

		// +GUI
		if guiMode == 1 {
			g.display(INFO, s.statusTabView, fmt.Sprintf("  Identity key for %s is verified", uid), nil)
		}
		// -GUI

		info(s.term, fmt.Sprintf("  Identity key for %s is verified", uid))
	} else if len(fprUid) > 1 {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, fmt.Sprintf("  Warning: %s is using an identity key which was verified for %s", uid, fprUid), nil)
		}
		// -GUI

		alert(s.term, fmt.Sprintf("  Warning: %s is using an identity key which was verified for %s", uid, fprUid))
	} else if s.config.HasFingerprint(uid) {

		// +GUI
		if guiMode == 1 {
			g.display(CRITICAL, s.statusTabView, fmt.Sprintf("  Identity key for %s is incorrect", uid), nil)
		}
		// -GUI

		critical(s.term, fmt.Sprintf("  Identity key for %s is incorrect", uid))
	} else {

		// +GUI
		if guiMode == 1 {
			g.display(ALERT, s.statusTabView, fmt.Sprintf("  Identity key for %s is not verified. You should use /otr-auth or /otr-authqa or /otr-authoob to verify their identity", uid), nil)
		}
		// -GUI

		alert(s.term, fmt.Sprintf("  Identity key for %s is not verified. You should use /otr-auth or /otr-authqa or /otr-authoob to verify their identity", uid))
	}
}

// INTERACTIVE FORM

// promptForForm runs an XEP-0004 form and collects responses from the user.
func promptForForm(term *terminal.Terminal, user, password, title, instructions string, fields []interface{}) error {
	info(term, "The server has requested the following information. Text that has come from the server will be shown in red.")

	// formStringForPrinting takes a string form the form and returns an
	// escaped version with codes to make it show as red.
	formStringForPrinting := func(s string) string {
		var line []byte

		line = appendTerminalEscaped(line, []byte(s))
		line = append(line, term.Escape.Reset...)
		return string(line)
	}

	write := func(s string) {
		term.Write([]byte(s))
	}

	var tmpDir string

	showMediaEntries := func(questionNumber int, medias [][]xmpp.Media) {
		if len(medias) == 0 {
			return
		}

		write("The following media blobs have been provided by the server with this question:\n")
		for i, media := range medias {
			for j, rep := range media {
				if j == 0 {
					write(fmt.Sprintf("  %d. ", i+1))
				} else {
					write("     ")
				}
				write(fmt.Sprintf("Data of type %s", formStringForPrinting(rep.MIMEType)))
				if len(rep.URI) > 0 {
					write(fmt.Sprintf(" at %s\n", formStringForPrinting(rep.URI)))
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
						write(", but failed to create temporary directory in which to save it: " + err.Error() + "\n")
						continue
					}
				}

				filename := filepath.Join(tmpDir, fmt.Sprintf("%d-%d-%d", questionNumber, i, j))
				if len(fileExt) > 0 {
					filename = filename + "." + fileExt
				}
				out, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					write(", but failed to create file in which to save it: " + err.Error() + "\n")
					continue
				}
				out.Write(rep.Data)
				out.Close()

				write(", saved in " + filename + "\n")
			}
		}

		write("\n")
	}

	var err error
	if len(title) > 0 {
		write(fmt.Sprintf("Title: %s\n", formStringForPrinting(title)))
	}
	if len(instructions) > 0 {
		write(fmt.Sprintf("Instructions: %s\n", formStringForPrinting(instructions)))
	}

	questionNumber := 0
	for _, field := range fields {
		questionNumber++
		write("\n")

		switch field := field.(type) {
		case *xmpp.FixedFormField:
			write(formStringForPrinting(field.Text))
			write("\n")
			questionNumber--

		case *xmpp.BooleanFormField:
			write(fmt.Sprintf("%d. %s\n\n", questionNumber, formStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)
			term.SetPrompt("Please enter yes, y, no or n: ")

		TryAgain:
			for {
				answer, err := term.ReadLine()
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
					write(fmt.Sprintf("CAPTCHA web page (only if not provided below): %s\n", formStringForPrinting(field.Default)))
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

			write(fmt.Sprintf("%d. %s\n\n", questionNumber, formStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			if len(field.Default) > 0 {
				write(fmt.Sprintf("Please enter response or leave blank for the default, which is '%s'\n", formStringForPrinting(field.Default)))
			} else {
				write("Please enter response")
			}
			term.SetPrompt("> ")
			if field.Private {
				field.Result, err = term.ReadPassword("> ")
			} else {
				field.Result, err = term.ReadLine()
			}
			if err != nil {
				return err
			}
			if len(field.Result) == 0 {
				field.Result = field.Default
			}

		case *xmpp.MultiTextFormField:
			write(fmt.Sprintf("%d. %s\n\n", questionNumber, formStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			write("Please enter one or more responses, terminated by an empty line\n")
			term.SetPrompt("> ")

			for {
				line, err := term.ReadLine()
				if err != nil {
					return err
				}
				if len(line) == 0 {
					break
				}
				field.Results = append(field.Results, line)
			}

		case *xmpp.SelectionFormField:
			write(fmt.Sprintf("%d. %s\n\n", questionNumber, formStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			for i, opt := range field.Values {
				write(fmt.Sprintf("  %d. %s\n\n", i+1, formStringForPrinting(opt)))
			}
			term.SetPrompt("Please enter the number of your selection: ")

		TryAgain2:
			for {
				answer, err := term.ReadLine()
				if err != nil {
					return err
				}
				answerNum, err := strconv.Atoi(answer)
				answerNum--
				if err != nil || answerNum < 0 || answerNum >= len(field.Values) {
					write("Cannot parse that reply. Try again.")
					continue TryAgain2
				}

				field.Result = answerNum
				break
			}

		case *xmpp.MultiSelectionFormField:
			write(fmt.Sprintf("%d. %s\n\n", questionNumber, formStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			for i, opt := range field.Values {
				write(fmt.Sprintf("  %d. %s\n\n", i+1, formStringForPrinting(opt)))
			}
			term.SetPrompt("Please enter the numbers of zero or more of the above, separated by spaces: ")

		TryAgain3:
			for {
				answer, err := term.ReadLine()
				if err != nil {
					return err
				}

				var candidateResults []int
				answers := strings.Fields(answer)
				for _, answerStr := range answers {
					answerNum, err := strconv.Atoi(answerStr)
					answerNum--
					if err != nil || answerNum < 0 || answerNum >= len(field.Values) {
						write("Cannot parse that reply. Please try again.")
						continue TryAgain3
					}
					for _, other := range candidateResults {
						if answerNum == other {
							write("Cannot have duplicates. Please try again.")
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
