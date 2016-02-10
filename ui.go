package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
		Log:                     xlib.NewLineLogger(xio),
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
		err := xlib.SetupRawLog(config.RawLogFile, xmppConfig)
		if err != nil {
			xio.Alert("Failed to open raw log file: " + err.Error())
			return
		}
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
