package main

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"code.google.com/p/go.crypto/ssh/terminal"
)

type uiCommand struct {
	name      string
	prototype interface{}
	desc      string
}

var uiCommands = []uiCommand{
	{"add", addCommand{}, "Request a subscription to another user's presence"},
	{"confirm", confirmCommand{}, "Confirm an inbound subscription request"},
	{"deny", denyCommand{}, "Deny an inbound subscription request"},
	{"help", helpCommand{}, "List known commands"},
	{"paste", pasteCommand{}, "Start interpreting text verbatim"},
	{"nopaste", noPasteCommand{}, "Stop interpreting text verbatim"},
	{"quit", quitCommand{}, "Quit the program"},
	{"roster", rosterCommand{}, "Display the current roster"},
	{"rosteredit", rosterEditCommand{}, "Write the roster to disk"},
	{"rostereditdone", rosterEditDoneCommand{}, "Load the edited roster from disk"},
	{"otr-auth", authCommand{}, "Authenticate a secure peer with a mutual, shared secret"},
	{"otr-authqa", authQACommand{}, "Authenticate a secure peer with a question and answer"},
	{"otr-authoob", authOobCommand{}, "Authenticate a secure peer with out-of-band fingerprint verification"},
	{"otr-end", endOTRCommand{}, "End an OTR session"},
	{"otr-start", otrCommand{}, "Start an OTR session with the given user"},
	{"otr-info", otrInfoCommand{}, "Print OTR information such as OTR fingerprint"},
	{"version", versionCommand{}, "Ask a Jabber client for its version"},
	{"statusupdates", toggleStatusUpdatesCommand{}, "Toggle if status updates are displayed"},
}

type addCommand struct {
	User string "uid"
}

type authCommand struct {
	User   string "uid"
	Secret string
}

type authQACommand struct {
	User     string "uid"
	Question string
	Secret   string
}

type authOobCommand struct {
	User        string "uid"
	Fingerprint string
}

type confirmCommand struct {
	User string "uid"
}

type denyCommand struct {
	User string "uid"
}

type endOTRCommand struct {
	User string "uid"
}

type helpCommand struct{}
type pasteCommand struct{}
type noPasteCommand struct{}

type quitCommand struct {
}

type rosterCommand struct {
	OnlineOnly bool "flag:online"
}

type rosterEditCommand struct{}
type rosterEditDoneCommand struct{}

type otrCommand struct {
	User string "uid"
}

type otrInfoCommand struct{}

type versionCommand struct {
	User string "uid"
}

type msgCommand struct {
	to  string
	msg string
}

type toggleStatusUpdatesCommand struct{}

func numPositionalFields(t reflect.Type) int {
	for i := 0; i < t.NumField(); i++ {
		if strings.HasPrefix(string(t.Field(i).Tag), "flag:") {
			return i
		}
	}
	return t.NumField()
}

func parseCommandForCompletion(commands []uiCommand, line []byte) (before, prefix []byte, isCommand, ok bool) {
	if len(line) == 0 || line[0] != '/' {
		return
	}

	spacePos := bytes.IndexByte(line, ' ')
	if spacePos == -1 {
		// We're completing a command name.
		before = line[:1]
		prefix = line[1:]
		isCommand = true
		ok = true
		return
	}

	command := string(line[1:spacePos])
	var prototype interface{}

	for _, cmd := range commands {
		if cmd.name == command {
			prototype = cmd.prototype
			break
		}
	}
	if prototype == nil {
		return
	}

	t := reflect.TypeOf(prototype)
	pos := spacePos
	fieldNum := -1
	fieldStart := 0
	inQuotes := false
	lastWasEscape := false
	numFields := numPositionalFields(t)

	skippingWhitespace := true
	for ; pos < len(line); pos++ {
		if skippingWhitespace {
			if line[pos] == ' ' {
				continue
			}
			skippingWhitespace = false
			fieldNum++
			fieldStart = pos
		}

		if lastWasEscape {
			lastWasEscape = false
			continue
		}

		if line[pos] == '\\' {
			lastWasEscape = true
			continue
		}

		if line[pos] == '"' {
			inQuotes = !inQuotes
		}

		if line[pos] == ' ' && !inQuotes {
			skippingWhitespace = true
		}
	}

	if skippingWhitespace {
		return
	}
	if fieldNum >= numFields {
		return
	}
	f := t.Field(fieldNum)
	if f.Tag != "uid" {
		return
	}
	ok = true
	isCommand = false
	before = line[:fieldStart]
	prefix = line[fieldStart:]
	return
}

// setOption updates the uiCommand, v, of type t given an option string with
// the "--" prefix already removed. It returns true on success.
func setOption(v reflect.Value, t reflect.Type, option string) bool {
	for i := 0; i < t.NumField(); i++ {
		fieldType := t.Field(i)
		tag := string(fieldType.Tag)
		if strings.HasPrefix(tag, "flag:") && tag[5:] == option {
			field := v.Field(i)
			if field.Bool() {
				return false // already set
			} else {
				field.SetBool(true)
				return true
			}
		}
	}

	return false
}

func parseCommand(commands []uiCommand, line []byte) (interface{}, string) {
	if len(line) == 0 || line[0] != '/' {
		panic("not a command")
	}

	spacePos := bytes.IndexByte(line, ' ')
	if spacePos == -1 {
		spacePos = len(line)
	}
	command := string(line[1:spacePos])
	var prototype interface{}

	for _, cmd := range commands {
		if cmd.name == command {
			prototype = cmd.prototype
			break
		}
	}
	if prototype == nil {
		return nil, "Unknown command: " + command
	}

	t := reflect.TypeOf(prototype)
	v := reflect.New(t)
	v = reflect.Indirect(v)
	pos := spacePos
	fieldNum := -1
	inQuotes := false
	lastWasEscape := false
	numFields := numPositionalFields(t)
	var field []byte

	skippingWhitespace := true
	for ; pos <= len(line); pos++ {
		if !skippingWhitespace && (pos == len(line) || (line[pos] == ' ' && !inQuotes && !lastWasEscape)) {
			skippingWhitespace = true
			strField := string(field)

			switch {
			case fieldNum < numFields:
				f := v.Field(fieldNum)
				f.Set(reflect.ValueOf(strField))
			case strings.HasPrefix(strField, "--"):
				if !setOption(v, t, strField[2:]) {
					return nil, "No such option " + strField + " for command"
				}
			default:
				return nil, "Too many arguments for command " + command + ". Expected " + strconv.Itoa(v.NumField())
			}
			field = field[:0]
			continue
		}

		if pos == len(line) {
			break
		}

		if lastWasEscape {
			field = append(field, line[pos])
			lastWasEscape = false
			continue
		}

		if skippingWhitespace {
			if line[pos] == ' ' {
				continue
			}
			skippingWhitespace = false
			fieldNum++
		}

		if line[pos] == '\\' {
			lastWasEscape = true
			continue
		}

		if line[pos] == '"' {
			inQuotes = !inQuotes
			continue
		}

		field = append(field, line[pos])
	}

	if fieldNum < numFields-1 {
		return nil, "Too few arguments for command " + command + ". Expected " + strconv.Itoa(v.NumField()) + ", but found " + strconv.Itoa(fieldNum+1)
	}

	return v.Interface(), ""
}

type Input struct {
	term                 *terminal.Terminal
	uidComplete          *priorityList
	uids                 []string
	commands             *priorityList
	lastKeyWasCompletion bool
	lock                 sync.Mutex
}

func (i *Input) AddUser(uid string) {
	i.lock.Lock()
	defer i.lock.Unlock()

	for _, existingUid := range i.uids {
		if existingUid == uid {
			return
		}
	}

	i.uidComplete.Insert([]byte(uid))
	i.uids = append(i.uids, uid)
}

func (i *Input) ProcessCommands(commandsChan chan<- interface{}) {
	i.commands = new(priorityList)
	for _, command := range uiCommands {
		i.commands.Insert([]byte(command.name))
	}

	autoCompleteCallback := func(line []byte, pos, key int) ([]byte, int) {
		return i.AutoComplete(line, pos, key)
	}

	var lastTarget string
	paste := false

	for {
		if paste {
			i.term.AutoCompleteCallback = nil
		} else {
			i.term.AutoCompleteCallback = autoCompleteCallback
		}

		line, err := i.term.ReadLine()
		if err != nil {
			close(commandsChan)
			return
		}
		if paste {
			l := string(line)
			if l == "/nopaste" {
				paste = false
			} else {
				commandsChan <- msgCommand{lastTarget, string(line)}
			}
			continue
		}
		if len(line) == 0 {
			continue
		}
		if line[0] == '/' {
			cmd, err := parseCommand(uiCommands, []byte(line))
			if len(err) != 0 {
				alert(i.term, err)
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
			if _, ok := cmd.(pasteCommand); ok {
				if len(lastTarget) == 0 {
					alert(i.term, "Can't enter paste mode without a destination. Send a message to someone to select the destination")
					continue
				}
				paste = true
				continue
			}
			if _, ok := cmd.(noPasteCommand); ok {
				paste = false
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
					lastTarget = possibleName
					line = line[pos+2:]
					break
				}
			}
		}
		i.lock.Unlock()

		if len(lastTarget) == 0 {
			warn(i.term, "Start typing a Jabber address and hit tab to send a message to someone")
			continue
		}
		commandsChan <- msgCommand{lastTarget, string(line)}
	}
}

func (input *Input) showHelp() {
	examples := make([]string, len(uiCommands))
	maxLen := 0

	for i, cmd := range uiCommands {
		line := "/" + cmd.name
		prototype := reflect.TypeOf(cmd.prototype)
		for j := 0; j < prototype.NumField(); j++ {
			if strings.HasPrefix(string(prototype.Field(j).Tag), "flag:") {
				line += " [--" + strings.ToLower(string(prototype.Field(j).Tag[5:])) + "]"
			} else {
				line += " <" + strings.ToLower(prototype.Field(j).Name) + ">"
			}
		}
		if l := len(line); l > maxLen {
			maxLen = l
		}
		examples[i] = line
	}

	for i, cmd := range uiCommands {
		line := examples[i]
		numSpaces := 1 + (maxLen - len(line))
		for j := 0; j < numSpaces; j++ {
			line += " "
		}
		line += cmd.desc
		info(input.term, line)
	}
}

var nameTerminator = []byte(": ")

func (i *Input) AutoComplete(line []byte, pos, key int) ([]byte, int) {
	const keyTab = 9

	if key != keyTab {
		i.lastKeyWasCompletion = false
		return nil, -1
	}

	i.lock.Lock()
	defer i.lock.Unlock()

	prefix := line[:pos]
	if i.lastKeyWasCompletion {
		// The user hit tab right after a completion, so we got
		// it wrong.
		if len(prefix) > 0 && prefix[0] == '/' {
			if bytes.IndexByte(prefix, ' ') == len(prefix)-1 {
				// We just completed a command.
				newCommand := i.commands.Next()
				var newLine []byte
				newLine = append(newLine, '/')
				newLine = append(newLine, newCommand...)
				newLine = append(newLine, ' ')
				newLine = append(newLine, line[pos:]...)
				return newLine, len(newCommand) + 2
			} else if prefix[len(prefix)-1] == ' ' {
				// We just completed a uid in a command.
				newUser := i.uidComplete.Next()
				spacePos := bytes.LastIndex(prefix[:len(prefix)-1], []byte{' '})
				var newLine []byte
				newLine = append(newLine, prefix[:spacePos]...)
				newLine = append(newLine, ' ')
				newLine = append(newLine, newUser...)
				newLine = append(newLine, ' ')
				newLine = append(newLine, line[pos:]...)
				return newLine, spacePos + 1 + len(newUser) + 1
			}
		} else if len(prefix) > 0 && prefix[0] != '/' && bytes.HasSuffix(prefix, nameTerminator) {
			// We just completed a uid at the start of a
			// conversation line.
			newUser := i.uidComplete.Next()
			var newLine []byte
			newLine = append(newLine, newUser...)
			newLine = append(newLine, nameTerminator...)
			newLine = append(newLine, line[pos:]...)
			return newLine, len(newUser) + 2
		}
	} else {
		if len(prefix) > 0 && prefix[0] == '/' {
			a, b, isCommand, ok := parseCommandForCompletion(uiCommands, prefix)
			if !ok {
				return line, pos
			}
			var newValue []byte
			if isCommand {
				newValue = i.commands.Find(b)
			} else {
				newValue = i.uidComplete.Find(b)
			}
			if len(newValue) == 0 {
				return line, pos
			}

			var newLine []byte
			newLine = append(newLine, a...)
			newLine = append(newLine, newValue...)
			newLine = append(newLine, ' ')
			newLine = append(newLine, line[pos:]...)
			i.lastKeyWasCompletion = true
			return newLine, len(a) + len(newValue) + 1
		} else if bytes.IndexAny(prefix, ": ") == -1 {
			// We're completing a uid at the start of a
			// conversation line.
			newUser := i.uidComplete.Find(prefix)
			if len(newUser) == 0 {
				return line, pos
			}

			var newLine []byte
			newLine = append(newLine, newUser...)
			newLine = append(newLine, nameTerminator...)
			newLine = append(newLine, line[pos:]...)
			i.lastKeyWasCompletion = true
			return newLine, len(newUser) + len(nameTerminator)
		}
	}

	i.lastKeyWasCompletion = false
	return nil, 0
}

type priorityListEntry struct {
	value []byte
	next  *priorityListEntry
}

type priorityList struct {
	head       *priorityListEntry
	lastPrefix []byte
	lastResult []byte
	n          int
}

func (pl *priorityList) Insert(value []byte) {
	ent := new(priorityListEntry)
	ent.next = pl.head
	ent.value = value
	pl.head = ent
}

func (pl *priorityList) findNth(prefix []byte, nth int) []byte {
	var cur, last *priorityListEntry
	cur = pl.head
	for n := 0; cur != nil; cur = cur.next {
		if bytes.HasPrefix(cur.value, prefix) {
			if n == nth {
				// move this entry to the top
				if last != nil {
					last.next = cur.next
				} else {
					pl.head = cur.next
				}
				cur.next = pl.head
				pl.head = cur
				pl.lastResult = cur.value
				return cur.value
			}
			n++
		}
		last = cur
	}

	return nil
}

func (pl *priorityList) Find(prefix []byte) []byte {
	pl.lastPrefix = make([]byte, len(prefix))
	copy(pl.lastPrefix, prefix)
	pl.n = 0

	return pl.findNth(prefix, 0)
}

func (pl *priorityList) Next() []byte {
	pl.n++
	result := pl.findNth(pl.lastPrefix, pl.n)
	if result == nil {
		pl.n = 1
		result = pl.findNth(pl.lastPrefix, pl.n)
	}
	return result
}
