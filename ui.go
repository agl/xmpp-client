package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/agl/xmpp-client/xmpp"
	"golang.org/x/crypto/otr"

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
		config.Password = password
	}

	xio.SetPrompt("> ")

	var createCallback xmpp.FormCallback
	if *createAccount {
		user, _, _ := xlib.UserDom(config.Account)
		createCallback = func(title, instructions string, fields []interface{}) error {
			return promptForForm(xio, user, password, title, instructions, fields)
		}
	}

	lgr := xlib.NewLineLogger(xio)

	s, err := xlib.Connect(xio, config, lgr, createCallback)
	if err != nil {
		xio.Alert("Failed to connect: " + err.Error())
		return
	}

	s.SignalPresence("")

	s.FetchRoster()

	input := NewInput(xio)

	commandChan := make(chan interface{})
	go input.ProcessCommands(s, commandChan)

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
		}
	}

	os.Stdout.Write([]byte("\n"))
}
