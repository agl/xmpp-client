package main

import (
	"bytes"
	"fmt"
	"github.com/agl/xmpp-client/xmpp"
	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/gdkpixbuf"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

// 0 == CLI
// 1 == GUI
var guiMode int = 1

var tagRed *gtk.TextTag
var tagGreen *gtk.TextTag
var tagYellow *gtk.TextTag

func stringDebug(string string) {
	fmt.Printf("\n")
	fmt.Printf("plain string: ")
	fmt.Printf("%s", string)
	fmt.Printf("\n")

	fmt.Printf("quoted string: ")
	fmt.Printf("%+q", string)
	fmt.Printf("\n\n")

	fmt.Printf("hex bytes: ")
	for i := 0; i < len(string); i++ {
		fmt.Printf("%x ", string[i])
	}
	fmt.Printf("\n\n")
}

type Purpose int

const (
	INFO Purpose = 1 + iota
	MSG_INCOMING
	STATUS
	ALERT
	WARN
	CRITICAL
)

type Status int

const (
	AVAILABLE Status = 1 + iota
	CHATTY
	AWAY
	XA
	DND
	OFFLINE
)

// Channel to pass GTK input-window contents to
// the existing outgoing-message code in ProcessCommands()
var guiOut chan string = make(chan string)

type GuiOutput struct {
	//	purpose Purpose
	//	tab     *gtk.TextView
	//	msg     string
	window        *gtk.Window
	statusTabView *gtk.TextView
	convoTabView  *gtk.TextView
	contactsView  *gtk.TextView
}

var g GuiOutput

func clearText(targetDisplay *gtk.TextView) {
	var start, end gtk.TextIter
	gdk.ThreadsEnter() // prevents unpredictable crashes
	buffer := targetDisplay.GetBuffer()
	buffer.GetStartIter(&start)
	buffer.GetEndIter(&end)
	buffer.Delete(&start, &end) // Deletes the buffer contents
	gdk.ThreadsLeave()
}

func displayText(purpose Purpose, targetDisplay *gtk.TextView, msg string) {
	var line string
	var beep bool
	switch purpose {
	case INFO:
		line = " (" + time.Now().Format(time.Kitchen) + ") " + msg + "\n\n"
	case MSG_INCOMING:
		line = msg + "\n" // to be enhanced with sender info, etc.
		beep = true
	case STATUS:
		line = msg + "\n\n"
	case ALERT:
		line = " * (" + time.Now().Format(time.Kitchen) + ") " + msg + "\n"
	case WARN:
		line = " * (" + time.Now().Format(time.Kitchen) + ") " + msg + "\n"
	case CRITICAL:
		line = " * (" + time.Now().Format(time.Kitchen) + ") " + msg + "\n"
	default:
		line = "Undefined message type"
	}
	var end gtk.TextIter
	gdk.ThreadsEnter() // Crashes without this when text exceeds window viewport
	buffer := targetDisplay.GetBuffer()
	buffer.GetEndIter(&end)
	buffer.Insert(&end, line) // this writes to the tab buffer
	if beep == true {
		gdk.Beep()
	}
	gdk.ThreadsLeave()
}

func displayContact(targetDisplay *gtk.TextView, msg string, color string, jid string) {
	var line string
	var tag *gtk.TextTag
	//var beep bool

	line = msg + "\n\n"
	var startIter gtk.TextIter
	var endIter gtk.TextIter
	gdk.ThreadsEnter()
	buffer := targetDisplay.GetBuffer()
	buffer.GetStartIter(&startIter)
	buffer.GetEndIter(&endIter)

	// build the tag here
	// color + jid for uniqueness

	//	switch color {
	//	case "red":
	//		//buffer.RemoveTagByName("red_"+jid, &startIter, &endIter)
	//		tag = buffer.CreateTag("red_"+jid, map[string]string{"background": "#FFcccc", "weight": "700"})
	//	case "yellow":
	//		//buffer.RemoveTagByName("yellow_"+jid, &startIter, &endIter)
	//		tag = buffer.CreateTag("yellow_"+jid, map[string]string{"background": "#FFFFaa", "weight": "700"})
	//	case "green":
	//		//buffer.RemoveTagByName("green_"+jid, &startIter, &endIter)
	//		tag = buffer.CreateTag("green_"+jid, map[string]string{"background": "#aaFFaa", "weight": "700"})
	//	}

	if color == "red" {
		tag = tagRed
	} else if color == "yellow" {
		tag = tagYellow
	} else if color == "green" {
		tag = tagGreen
	}

	buffer.InsertWithTag(&endIter, line, tag)

	// String generated by the button-release event
	/*
		u := "http://www.google.com"

		// The JID below is used as the tag-name, which must be unique. Recurs below.

		tag.SetData(jid, unsafe.Pointer(&u))

		targetDisplay.Connect("event-after", func(ctx *glib.CallbackContext) {
			arg := ctx.Args(0)
			if ev := *(**gdk.EventAny)(unsafe.Pointer(&arg)); ev.Type != gdk.BUTTON_RELEASE {
				return
			}
			ev := *(**gdk.EventButton)(unsafe.Pointer(&arg))
			var iter gtk.TextIter
			targetDisplay.GetIterAtLocation(&iter, int(ev.X), int(ev.Y))
			tags := iter.GetTags()

			for n := uint(0); n < tags.Length(); n++ {
				vv := tags.NthData(n)

				// The JID below is used as the tag-name, which must be unique.

				if data := (*string)(gtk.NewTextTagFromPointer(vv).GetData(jid)); data != nil {
					fmt.Println(*data)
				}
			}

		})
	*/
	gdk.ThreadsLeave()
}

func initializeGTK() {
	gtk.Init(nil)
	glib.ThreadInit(nil)
	gdk.ThreadsInit()
}

func buildGUI() (window *gtk.Window, statusTabView *gtk.TextView, convoTabView *gtk.TextView, contactsView *gtk.TextView) {
	//--------------------------------------------------------
	//--------------------------------------------------------
	// Widget declarations
	//--------------------------------------------------------
	//--------------------------------------------------------

	//--------------------------------------------------------
	// GtkWindow
	//--------------------------------------------------------
	window = gtk.NewWindow(gtk.WINDOW_TOPLEVEL) // Top-level window
	window.SetPosition(gtk.WIN_POS_CENTER)
	window.SetTitle("XMPP-CLIENT (GTK)")
	window.SetIconName("gtk-network") // gtk stock icon
	window.Connect("destroy", gtk.MainQuit)

	//--------------------------------------------------------
	// GtkVBox
	//--------------------------------------------------------
	vbox := gtk.NewVBox(false, 1) // Top-level vbox container

	//--------------------------------------------------------
	// GtkMenuBar
	//--------------------------------------------------------
	menubar := gtk.NewMenuBar()
	vbox.PackStart(menubar, false, false, 0)

	//--------------------------------------------------------
	// GtkMenuItem (top tool menu)
	//--------------------------------------------------------
	cascademenu := gtk.NewMenuItemWithMnemonic("_File")
	menubar.Append(cascademenu)
	submenu := gtk.NewMenu()
	cascademenu.SetSubmenu(submenu)

	var menuitem *gtk.MenuItem
	menuitem = gtk.NewMenuItemWithMnemonic("E_xit")
	menuitem.Connect("activate", func() {
		gtk.MainQuit()
	})
	submenu.Append(menuitem)

	cascademenu = gtk.NewMenuItemWithMnemonic("_Help")
	menubar.Append(cascademenu)
	submenu = gtk.NewMenu()
	cascademenu.SetSubmenu(submenu)

	menuitem = gtk.NewMenuItemWithMnemonic("_About")
	menuitem.Connect("activate", func() {
		dialog := gtk.NewAboutDialog()
		dialog.SetName("Go-Gtk Demo!")
		dialog.SetProgramName("demo")
		//		dialog.SetAuthors(authors())
		dir, _ := filepath.Split(os.Args[0])
		imagefile := filepath.Join(dir, "../../data/mattn-logo.png")
		pixbuf, _ := gdkpixbuf.NewPixbufFromFile(imagefile)
		dialog.SetLogo(pixbuf)
		dialog.SetLicense("The library is available under the same terms and conditions as the Go, the BSD style license, and the LGPL (Lesser GNU Public License). The idea is that if you can use Go (and Gtk) in a project, you should also be able to use go-gtk.")
		dialog.SetWrapLicense(true)
		dialog.Run()
		dialog.Destroy()
	})
	submenu.Append(menuitem)

	//--------------------------------------------------------
	// GtkHPaned and GtkVPaned plus frames and boxes
	//--------------------------------------------------------
	hpaned := gtk.NewHPaned()           // Horizontal pane pair
	frameH1 := gtk.NewFrame("")         // Frame for left pane (contains vpaned directly)
	frameH2 := gtk.NewFrame("Contacts") // Frame for right pane
	frameboxH2 := gtk.NewVBox(false, 1) // Framebox for right pane (contains contact list)

	vpaned := gtk.NewVPaned()           // Vertical pane pair (nested in frameH1)
	frameV1 := gtk.NewFrame("")         // Frame for top pane
	frameV2 := gtk.NewFrame("Input")    // Frame for bottom pane (contains notebook/tabs directly)
	frameboxV2 := gtk.NewVBox(false, 1) // Framebox for bottom pane (contains input box)

	//--------------------------------------------------------
	// GtkNotebook for tabbed display
	//--------------------------------------------------------
	tabs := gtk.NewNotebook() // Tabbed conversation log
	tabs.SetTabPos(gtk.POS_BOTTOM)

	//
	// Always-present server & client status message tab
	//

	statusTabFrame := gtk.NewFrame("Server & client status")
	statusTabFrame.SetLabelAlign(0.5, 0.5) // middle top
	tabs.AppendPage(statusTabFrame, gtk.NewLabel("Status"))

	statusTabScrollWin := gtk.NewScrolledWindow(nil, nil)
	statusTabScrollWin.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	statusTabScrollWin.SetShadowType(gtk.SHADOW_IN)

	statusTabView = gtk.NewTextView()
	statusTabView.SetWrapMode(gtk.WRAP_WORD_CHAR)
	statusTabView.SetEditable(false)
	statusTabView.SetCursorVisible(false)

	var statusTabStartIter gtk.TextIter
	var statusTabEndIter gtk.TextIter

	statusTabBuffer := statusTabView.GetBuffer()
	statusTabBuffer.GetStartIter(&statusTabStartIter)
	statusTabBuffer.GetEndIter(&statusTabEndIter)
	statusTabScrollWin.Add(statusTabView)
	statusTabFrame.Add(statusTabScrollWin)

	// no need for a channel here
	statusTabBuffer.Connect("changed", func() {
		statusTabBuffer.GetEndIter(&statusTabEndIter) // avoids problems from display()
		statusTabView.ScrollToIter(&statusTabEndIter, 0, false, 0, 0)
	})

	//
	// Test conversation tab
	//

	convoTabFrame := gtk.NewFrame("Test conversation")
	convoTabFrame.SetLabelAlign(0.5, 0.5) // middle top
	tabs.AppendPage(convoTabFrame, gtk.NewLabel("Conversation"))

	convoTabScrollWin := gtk.NewScrolledWindow(nil, nil)
	convoTabScrollWin.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	convoTabScrollWin.SetShadowType(gtk.SHADOW_IN)

	convoTabView = gtk.NewTextView()
	convoTabView.SetWrapMode(gtk.WRAP_WORD_CHAR)
	convoTabView.SetEditable(false)
	convoTabView.SetCursorVisible(false)

	var convoTabStartIter gtk.TextIter
	var convoTabEndIter gtk.TextIter

	convoTabBuffer := convoTabView.GetBuffer()
	convoTabBuffer.GetStartIter(&convoTabStartIter)
	convoTabBuffer.GetEndIter(&convoTabEndIter)

	// Move these to nesting section below when ready
	convoTabScrollWin.Add(convoTabView)
	convoTabFrame.Add(convoTabScrollWin)

	// no need for a channel here
	convoTabBuffer.Connect("changed", func() {
		convoTabBuffer.GetEndIter(&convoTabEndIter) // avoids problems from display()
		convoTabView.ScrollToIter(&convoTabEndIter, 0, false, 0, 0)
	})

	/*
		for n := 0; n <= maxDwarves; n++ {

			page := gtk.NewFrame("Conversation with " + dwarves[n])
			page.SetLabelAlign(0.5, 0.5) // middle top

			tabs.AppendPage(page, gtk.NewLabel(dwarves[n]))

			scrolledWindow := gtk.NewScrolledWindow(nil, nil)
			scrolledWindow.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
			scrolledWindow.SetShadowType(gtk.SHADOW_IN)

			textView := gtk.NewTextView()
			textView.SetWrapMode(gtk.WRAP_WORD_CHAR)
			textView.SetEditable(true)
			textView.SetCursorVisible(true)
			var iter gtk.TextIter
			buffer := textView.GetBuffer()

			buffer.GetStartIter(&iter)
			buffer.Insert(&iter, "\n\n     Hello World! This is "+dwarves[n]+" speaking.")

			scrolledWindow.Add(textView)

			page.Add(scrolledWindow)
		}
	*/

	//
	// Here we implement input functionality.
	//

	inputScroller := gtk.NewScrolledWindow(nil, nil)
	inputScroller.SetSizeRequest(0, 1)
	inputScroller.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	inputScroller.SetShadowType(gtk.SHADOW_IN)

	inputView := gtk.NewTextView()
	inputView.SetEditable(true)
	inputView.SetWrapMode(gtk.WRAP_WORD_CHAR)
	inputView.SetCursorVisible(true)

	inputBuffer := inputView.GetBuffer()

	var inputStartIter gtk.TextIter
	var inputEndIter gtk.TextIter

	event := make(chan interface{})

	// "key-press-event" below is a SIGNAL valid for GtkTextView.
	// Only key-press-event signals will trigger events here.
	inputView.Connect("key-press-event", func(ctx *glib.CallbackContext) {
		arg := ctx.Args(0)
		event <- *(**gdk.EventKey)(unsafe.Pointer(&arg))
	})

	go func() (outgoing string) {
		for {
			e := <-event
			switch ev := e.(type) {

			case *gdk.EventKey:
				// look for the enter key
				if int(ev.Keyval) == 65293 {

					//+DEBUGGING
					fmt.Println("key-press-event key value field:", ev.Keyval)
					//-DEBUGGING

					inputBuffer.GetStartIter(&inputStartIter)
					inputBuffer.GetEndIter(&inputEndIter)

					inputBuffer.SetModified(false)

					//+DEBUGGING
					//					if inputBuffer.GetModified() == false {
					//						fmt.Printf("inputBuffer is unchanged \n")
					//					} else if inputBuffer.GetModified() == true {
					//					fmt.Printf("inputBuffer changed \n")
					//			}
					//
					//-DEBUGGING

					gdk.ThreadsEnter()

					// The iters need to be reset in case
					// alerts or other actions
					// have occured in the tab buffer.

					convoTabBuffer.GetStartIter(&convoTabStartIter)
					convoTabBuffer.GetEndIter(&convoTabEndIter)

					// Content of the outgoing message goes into a string.
					outgoingRaw := inputBuffer.GetText(&inputStartIter, &inputEndIter, true)

					// +Debug
					stringDebug(outgoingRaw)
					// -Debug

					// Trim off the carriage return \x0a so the command parser won't barf,
					// but keep the raw input to pass to the output text buffer.
					outgoingClean := string(bytes.TrimSuffix([]byte(outgoingRaw), []byte("\n")))

					// +Debug
					stringDebug(outgoingClean)
					// -Debug

					if guiMode == 1 {
						// Send the message into the outgoing commands channel.
						// This can't be running during non-gui because it blocks the program.
						// The channel waits indefinitely to be read.
						guiOut <- outgoingClean
					}

					// Write the outgoing message to the output buffer.
					convoTabBuffer.Insert(&convoTabEndIter, outgoingRaw+"\n")

					inputBuffer.GetStartIter(&inputStartIter) // Get beginning and end of input-box text
					inputBuffer.GetEndIter(&inputEndIter)

					inputBuffer.Delete(&inputStartIter, &inputEndIter) // Clear the input box

					gdk.ThreadsLeave()
				}
			}
		}
		return
	}()

	//--------------------------------------------------------
	// Contacts pane
	//--------------------------------------------------------

	contactsScrollWin := gtk.NewScrolledWindow(nil, nil)
	contactsScrollWin.SetSizeRequest(0, 1)
	contactsScrollWin.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	contactsScrollWin.SetShadowType(gtk.SHADOW_IN)

	contactsView = gtk.NewTextView()
	contactsView.SetWrapMode(gtk.WRAP_WORD_CHAR)
	contactsView.SetEditable(false)
	contactsView.SetCursorVisible(true)

	var contactsStartIter gtk.TextIter
	var contactsEndIter gtk.TextIter

	contactsBuffer := contactsView.GetBuffer()

	tagRed = contactsBuffer.CreateTag("red", map[string]string{"background": "#FFcccc", "weight": "700"})
	tagGreen = contactsBuffer.CreateTag("green", map[string]string{"background": "#aaFFaa", "weight": "700"})
	tagYellow = contactsBuffer.CreateTag("yellow", map[string]string{"background": "#FFFFaa", "weight": "700"})

	contactsBuffer.GetStartIter(&contactsStartIter)
	contactsBuffer.GetEndIter(&contactsStartIter)

	contactsBuffer.Connect("changed", func() {
		contactsBuffer.GetEndIter(&contactsEndIter) // avoids problems from display()
		contactsView.ScrollToIter(&contactsEndIter, 0, false, 0, 0)
	})

	vbox.Add(hpaned)
	hpaned.Pack1(frameH1, false, false)
	hpaned.Pack2(frameH2, false, false)
	vpaned.Pack1(frameV1, false, false)
	vpaned.Pack2(frameV2, false, false)
	frameH1.Add(vpaned)
	contactsScrollWin.Add(contactsView)
	frameboxH2.Add(contactsScrollWin)
	frameH2.Add(frameboxH2)
	frameV1.Add(tabs)
	frameV2.Add(frameboxV2)
	inputScroller.Add(inputView)
	frameboxV2.Add(inputScroller)
	window.Add(vbox)

	window.SetSizeRequest(800, 600)

	g = GuiOutput{
		window:        window,
		statusTabView: statusTabView,
		convoTabView:  convoTabView,
		contactsView:  contactsView,
	}

	return
}

func (i *Input) GuiProcessCommands(commandsChan chan<- interface{}) {
	i.commands = new(priorityList)
	for _, command := range uiCommands {
		i.commands.Insert(command.name)
	}

	//		autoCompleteCallback := func(line string, pos int, key rune) (string, int, bool) {
	//			return i.AutoComplete(line, pos, key)
	//		}

	//		paste := false

	setPromptIsEncrypted := make(chan bool)

	for {

		line := <-guiOut

		// this works:
		if len(line) == 0 {
			continue
		}

		// command prefix
		if line[0] == '/' {
			cmd, err := parseCommand(uiCommands, []byte(line))
			if len(err) != 0 {
				alert(i.term, err) // term
				continue
			}
			// authCommand is turned into authQACommand with an
			// empty question.
			if authCmd, ok := cmd.(authCommand); ok {
				cmd = authQACommand{
					User:   authCmd.User,
					Secret: authCmd.Secret,
				}
			}
			if _, ok := cmd.(helpCommand); ok {
				i.showHelp()
				continue
			}

			if _, ok := cmd.(closeCommand); ok {
				i.lastTarget = ""
				i.term.SetPrompt("> ") // term: this is not a simple one
				continue
			}
			if cmd != nil {
				commandsChan <- cmd
			}
			continue
		}

		i.lock.Lock()
		if pos := strings.Index(line, string(nameTerminator)); pos > 0 {
			possibleName := line[:pos]
			for _, uid := range i.uids {
				if possibleName == uid {
					i.lastTarget = possibleName
					line = line[pos+2:]
					break
				}
			}
		}
		i.lock.Unlock()

		if len(i.lastTarget) == 0 {

			// add gui output for alert

			warn(i.term, "Start typing a Jabber address and hit tab to send a message to someone")
			continue
		}

		// Here's where an IM is passed into a channel to be sent.
		// in the MainLoop. msgCommand is the type for IMs.
		commandsChan <- msgCommand{i.lastTarget, string(line), setPromptIsEncrypted}
		isEncrypted := <-setPromptIsEncrypted
		i.SetPromptForTarget(i.lastTarget, isEncrypted)
	}
}

// The following method is supplied with ClientPresence stanzas
// arriving over the stanzaChan in the MainLoop.
// To Do: Add a GUI toggle to choose --online or not.

func (s *Session) guiProcessPresence(stanza *xmpp.ClientPresence) {

	gone := false

	switch stanza.Type {
	case "subscribe":
		// This is a subscription request
		jid := xmpp.RemoveResourceFromJid(stanza.From)
		displayText(INFO, g.statusTabView, jid+" wishes to see when you're online. Use '/confirm "+jid+"' to confirm (or likewise with /deny to decline)")
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

	var prefix []byte
	var guiLine []byte

	prefix = append(prefix, []byte(fmt.Sprintf(" (%s) ", time.Now().Format(time.Kitchen)))...)

	guiLine = append(guiLine, []byte(from)...)
	guiLine = append(guiLine, ':')
	guiLine = append(guiLine, ' ')
	if gone {
		guiLine = append(guiLine, []byte("offline")...)
	} else if len(stanza.Show) > 0 {
		guiLine = append(guiLine, []byte(stanza.Show)...)
	} else {
		guiLine = append(guiLine, []byte("online")...)
	}
	guiLine = append(guiLine, ' ')
	guiLine = append(guiLine, []byte(stanza.Status)...)

	// output to a tab -- more to do when these differentiate

	displayText(STATUS, g.statusTabView, fmt.Sprintf("%v", string(prefix)+string(guiLine)))

	// call the moved RosterCommand code

	maxLen := 0
	for _, item := range s.roster {
		if maxLen < len(item.Jid) {
			maxLen = len(item.Jid)
		}
	}

	clearText(g.contactsView) // clean up Contacts window before posting update

	// need to clear or delete tag table?

	for _, item := range s.roster {
		state, ok := s.knownStates[item.Jid]

		line := ""
		if ok {
			line += " [*] "
			//	} else if cmd.OnlineOnly {	// Replace this with a GUI toggle.
			//		continue
		} else {
			line += " [ ] "
		}

		line += item.Jid
		numSpaces := 1 + (maxLen - len(item.Jid))
		for i := 0; i < numSpaces; i++ {
			line += " "
		}
		line += item.Subscription + "\t" + item.Name // that's a tab
		if ok {
			line += "\t" + state
		}
		if (ok && (state == "")) || (state == "chat") {
			displayContact(g.contactsView, line, "green", string(item.Jid))
		} else if ok && (state != "") {
			displayContact(g.contactsView, line, "yellow", string(item.Jid))
		} else {
			displayContact(g.contactsView, line, "red", string(item.Jid))
		}
	}
}