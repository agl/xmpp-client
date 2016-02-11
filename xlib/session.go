package xlib

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/agl/xmpp-client/caroots"
	"github.com/agl/xmpp-client/xmpp"
	"golang.org/x/crypto/otr"
)

var NEWLINE = []byte{'\n'}

// OTRWhitespaceTagStart may be appended to plaintext messages to signal to the
// remote client that we support OTR. It should be followed by one of the
// version specific tags, below. See "Tagged plaintext messages" in
// http://www.cypherpunks.ca/otr/Protocol-v3-4.0.0.html.
var OTRWhitespaceTagStart = []byte("\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20")

var OTRWhiteSpaceTagV1 = []byte("\x20\x09\x20\x09\x20\x20\x09\x20")
var OTRWhiteSpaceTagV2 = []byte("\x20\x20\x09\x09\x20\x20\x09\x20")
var OTRWhiteSpaceTagV3 = []byte("\x20\x20\x09\x09\x20\x20\x09\x09")

var OTRWhitespaceTag = append(OTRWhitespaceTagStart, OTRWhiteSpaceTagV2...)

type Session struct {
	account string
	*xmpp.Conn
	Xio    XIO
	roster []xmpp.RosterEntry
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
	ignored     map[string]struct{}
	rosterReply <-chan xmpp.Stanza
	// Formerly part of input
	// lock protects, uids, uidComplete and lastTarget
	lock        sync.Mutex
	uids        []string
	uidComplete *PriorityList
	lastTarget  string
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

func (s *Session) AddUser(uid string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, existingUid := range s.uids {
		if existingUid == uid {
			return
		}
	}

	s.uidComplete.Insert(uid)
	s.uids = append(s.uids, uid)
}

func (s *Session) CompleteLock() {
	s.lock.Lock()
}

func (s *Session) CompleteUnlock() {
	s.lock.Unlock()
}

func (s *Session) CompleteNext() string {
	return s.uidComplete.Next()
}

func (s *Session) CompleteFind(f string) (string, bool) {
	return s.uidComplete.Find(f)
}

func (s *Session) ReadMessages(stanzaChan chan<- xmpp.Stanza) {
	defer close(stanzaChan)

	for {
		stanza, err := s.Next()
		if err != nil {
			s.Xio.Alert(err.Error())
			return
		}
		stanzaChan <- stanza
	}
}

func (s *Session) ProcessIQ(stanza *xmpp.ClientIQ) interface{} {
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
			s.Xio.Warn("Ignoring roster IQ from bad address: " + stanza.From)
			return nil
		}
		var roster xmpp.Roster
		if err := xml.NewDecoder(bytes.NewBuffer(stanza.Query)).Decode(&roster); err != nil || len(roster.Item) == 0 {
			s.Xio.Warn("Failed to parse roster push IQ")
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
			s.AddUser(entry.Jid)
		}
		return xmpp.EmptyReply{}
	default:
		s.Xio.Info("Unknown IQ: " + startElem.Name.Space + " " + startElem.Name.Local)
	}

	return nil
}

func (s *Session) HandleConfirmOrDeny(jid string, isConfirm bool) {
	id, ok := s.pendingSubscribes[jid]
	if !ok {
		s.Xio.Warn("No pending subscription from " + jid)
		return
	}
	delete(s.pendingSubscribes, id)
	typ := "unsubscribed"
	if isConfirm {
		typ = "subscribed"
	}
	if err := s.SendPresence(jid, typ, id); err != nil {
		s.Xio.Alert("Error sending presence stanza: " + err.Error())
	}
}

func (s *Session) IgnoreUser(uid string) {
	if _, ok := s.ignored[uid]; ok {
		s.Xio.Info("Already ignoring " + uid)
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	hasContact := false

	for _, existingUid := range s.uids {
		if existingUid == uid {
			hasContact = true
		}
	}

	if hasContact {
		s.Xio.Info(fmt.Sprintf("Ignoring messages from %s for the duration of this session", uid))
	} else {
		s.Xio.Warn(fmt.Sprintf("%s isn't in your contact list... ignoring anyway for the duration of this session!", uid))
	}

	s.ignored[uid] = struct{}{}
	s.Xio.Info(fmt.Sprintf("Use '/unignore %s' to continue receiving messages from them.", uid))
}

func (s *Session) UnignoreUser(uid string) {
	if _, ok := s.ignored[uid]; !ok {
		s.Xio.Info("No ignore registered for " + uid)
		return
	}

	s.Xio.Info("No longer ignoring messages from " + uid)
	delete(s.ignored, uid)
}

func (s *Session) IgnoreList() {
	var ignored []string

	for ignoredUser, _ := range s.ignored {
		ignored = append(ignored, ignoredUser)
	}
	sort.Strings(ignored)

	s.Xio.Info("Ignoring messages from these users for the duration of the session:")
	for _, ignoredUser := range ignored {
		s.Xio.Info("  " + ignoredUser)
	}
}

func (s *Session) ProcessClientMessage(stanza *xmpp.ClientMessage) {
	from := xmpp.RemoveResourceFromJid(stanza.From)
	to := xmpp.RemoveResourceFromJid(stanza.To)

	if _, ok := s.ignored[from]; ok {
		return
	}

	if stanza.Type == "error" {
		s.Xio.Alert("Error reported from " + from + ": " + stanza.Body)
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
		s.Xio.Alert("While processing message from " + from + ": " + err.Error())
		s.Send(stanza.From, otr.ErrorPrefix+"Error processing message")
	}
	for _, msg := range toSend {
		s.Send(stanza.From, string(msg))
	}
	switch change {
	case otr.NewKeys:
		s.SetPromptForTarget(from, true)
		s.Xio.Info(fmt.Sprintf("New OTR session with %s established", from))
		s.PrintConversationInfo(from, conversation)
	case otr.ConversationEnded:
		s.SetPromptForTarget(from, false)
		// This is probably unsafe without a policy that _forces_ crypto to
		// _everyone_ by default and refuses plaintext. Users might not notice
		// their buddy has ended a session, which they have also ended, and they
		// might send a plain text message. So we should ensure they _want_ this
		// feature and have set it as an explicit preference.
		if s.config.OTRAutoTearDown {
			if s.conversations[from] == nil {
				s.Xio.Alert(fmt.Sprintf("No secure session established; unable to automatically tear down OTR conversation with %s.", from))
				break
			} else {
				s.Xio.Info(fmt.Sprintf("%s has ended the secure conversation.", from))
				msgs := conversation.End()
				for _, msg := range msgs {
					s.Send(from, string(msg))
				}
				s.Xio.Info(fmt.Sprintf("Secure session with %s has been automatically ended. Messages will be sent in the clear until another OTR session is established.", from))
			}
		} else {
			s.Xio.Info(fmt.Sprintf("%s has ended the secure conversation. You should do likewise with /otr-end %s", from, from))
		}
	case otr.SMPSecretNeeded:
		s.Xio.Info(fmt.Sprintf("%s is attempting to authenticate. Please supply mutual shared secret with /otr-auth user secret", from))
		if question := conversation.SMPQuestion(); len(question) > 0 {
			s.Xio.Info(fmt.Sprintf("%s asks: %s", from, question))
		}
	case otr.SMPComplete:
		s.Xio.Info(fmt.Sprintf("Authentication with %s successful", from))
		fpr := conversation.TheirPublicKey.Fingerprint()
		if len(s.config.UserIdForFingerprint(fpr)) == 0 {
			s.config.KnownFingerprints = append(s.config.KnownFingerprints, KnownFingerprint{fingerprint: fpr, UserId: from})
		}
		s.config.Save()
	case otr.SMPFailed:
		s.Xio.Alert(fmt.Sprintf("Authentication with %s failed", from))
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
				s.Xio.Info(fmt.Sprintf("%s appears to support OTRv1. You should encourage them to upgrade their OTR client!", from))
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
		s.Xio.Info(fmt.Sprintf("%s appears to support OTRv%d. We are attempting to start an OTR session with them.", from, detectedOTRVersion))
		s.Send(from, otr.QueryMessage)
	} else if s.config.OTRAutoStartSession && detectedOTRVersion == 1 {
		s.Xio.Info(fmt.Sprintf("%s appears to support OTRv%d. You should encourage them to upgrade their OTR client!", from, detectedOTRVersion))
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
			s.Xio.Alert("Can not parse Delayed Delivery timestamp, using quoted string instead.")
			timestamp = fmt.Sprintf("%q", stanza.Delay.Stamp)
		}
	} else {
		messageTime = time.Now()
	}
	if len(timestamp) == 0 {
		timestamp = messageTime.Format(time.Stamp)
	}

	s.Xio.Message(timestamp, from, to, out, encrypted, s.config.Bell)
	s.maybeNotify()
}

func (s *Session) LastAction() {
	s.lastActionTime = time.Now()
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
			s.Xio.Alert("Failed to run notify command: " + err.Error())
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

func (s *Session) ProcessPresence(stanza *xmpp.ClientPresence) {
	gone := false

	switch stanza.Type {
	case "subscribe":
		// This is a subscription request
		jid := xmpp.RemoveResourceFromJid(stanza.From)
		s.Xio.Info(jid + " wishes to see when you're online. Use '/confirm " + jid + "' to confirm (or likewise with /deny to decline)")
		s.pendingSubscribes[jid] = stanza.Id
		s.AddUser(jid)
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
		s.Xio.StatusUpdate(timestamp, from, stanza.Show, stanza.Status, gone)
	}
}

func (s *Session) awaitVersionReply(ch <-chan xmpp.Stanza, user string) {
	stanza, ok := <-ch
	if !ok {
		s.Xio.Warn("Version request to " + user + " timed out")
		return
	}
	reply, ok := stanza.Value.(*xmpp.ClientIQ)
	if !ok {
		s.Xio.Warn("Version request to " + user + " resulted in bad reply type")
		return
	}

	if reply.Type == "error" {
		s.Xio.Warn("Version request to " + user + " resulted in XMPP error")
		return
	} else if reply.Type != "result" {
		s.Xio.Warn("Version request to " + user + " resulted in response with unknown type: " + reply.Type)
		return
	}

	buf := bytes.NewBuffer(reply.Query)
	var versionReply xmpp.VersionReply
	if err := xml.NewDecoder(buf).Decode(&versionReply); err != nil {
		s.Xio.Warn("Failed to parse version reply from " + user + ": " + err.Error())
		return
	}

	s.Xio.Info(fmt.Sprintf("Version reply from %s: %#v", user, versionReply))
}

// editRoster runs in a goroutine and writes the roster to a file that the user
// can edit.
func (s *Session) EditRoster(roster []xmpp.RosterEntry) {
	// In case the editor rewrites the file, we work inside a temp
	// directory.
	dir, err := ioutil.TempDir("" /* system default temp dir */, "xmpp-client")
	if err != nil {
		s.Xio.Alert("Failed to create temp dir to edit roster: " + err.Error())
		return
	}

	mode, err := os.Stat(dir)
	if err != nil || mode.Mode()&os.ModePerm != 0700 {
		panic("broken system libraries gave us an insecure temp dir")
	}

	fileName := filepath.Join(dir, "roster")
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		s.Xio.Alert("Failed to create temp file: " + err.Error())
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
		escapedJids[i] = EscapeNonASCII(item.Jid)
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
			line += "name:" + EscapeNonASCII(item.Name)
			if len(item.Group) > 0 {
				line += "\t"
			}
		}

		for j, group := range item.Group {
			if j > 0 {
				line += "\t"
			}
			line += "group:" + EscapeNonASCII(group)
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

func (s *Session) LoadEditedRoster(edit rosterEdit) {
	contents, err := ioutil.ReadFile(edit.fileName)
	if err != nil {
		s.Xio.Alert("Failed to load edited roster: " + err.Error())
		return
	}
	os.Remove(edit.fileName)
	os.Remove(filepath.Dir(edit.fileName))

	edit.isComplete = true
	edit.contents = contents
	s.pendingRosterChan <- &edit
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

func (s *Session) processEditedRoster(edit *rosterEdit) bool {
	parsedRoster := make(map[string]xmpp.RosterEntry)
	lines := bytes.Split(edit.contents, NEWLINE)
	tab := []byte{'\t'}

	// Parse roster entries from the file.
	for i, line := range lines {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		parts := bytes.Split(line, tab)

		var entry xmpp.RosterEntry
		var err error

		if entry.Jid, err = UnescapeNonASCII(string(string(parts[0]))); err != nil {
			s.Xio.Alert(fmt.Sprintf("Failed to parse JID on line %d: %s", i+1, err))
			return false
		}
		for _, part := range parts[1:] {
			if len(part) == 0 {
				continue
			}

			pos := bytes.IndexByte(part, ':')
			if pos == -1 {
				s.Xio.Alert(fmt.Sprintf("Failed to find colon in item on line %d", i+1))
				return false
			}

			typ := string(part[:pos])
			value, err := UnescapeNonASCII(string(part[pos+1:]))
			if err != nil {
				s.Xio.Alert(fmt.Sprintf("Failed to unescape item on line %d: %s", i+1, err))
				return false
			}

			switch typ {
			case "name":
				if len(entry.Name) > 0 {
					s.Xio.Alert(fmt.Sprintf("Multiple names given for contact on line %d", i+1))
					return false
				}
				entry.Name = value
			case "group":
				if len(value) > 0 {
					entry.Group = append(entry.Group, value)
				}
			default:
				s.Xio.Alert(fmt.Sprintf("Unknown item tag '%s' on line %d", typ, i+1))
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
		s.Xio.Info("Deleting roster entry for " + jid)
		_, _, err := s.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:          jid,
				Subscription: "remove",
			},
		})
		if err != nil {
			s.Xio.Alert("Failed to remove roster entry: " + err.Error())
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
		s.Xio.Info("Updating roster entry for " + entry.Jid)
		_, _, err := s.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:   entry.Jid,
				Name:  entry.Name,
				Group: entry.Group,
			},
		})
		if err != nil {
			s.Xio.Alert("Failed to update roster entry: " + err.Error())
		}
	}

	for _, entry := range toAdd {
		s.Xio.Info("Adding roster entry for " + entry.Jid)
		_, _, err := s.SendIQ("" /* to the server */, "set", xmpp.RosterRequest{
			Item: xmpp.RosterRequestItem{
				Jid:   entry.Jid,
				Name:  entry.Name,
				Group: entry.Group,
			},
		})
		if err != nil {
			s.Xio.Alert("Failed to add roster entry: " + err.Error())
		}
	}

	return true
}

func NewSession(config *Config, xio XIO) (s *Session) {
	s = &Session{
		account:           config.Account,
		Xio:               xio,
		conversations:     make(map[string]*otr.Conversation),
		knownStates:       make(map[string]string),
		privateKey:        new(otr.PrivateKey),
		config:            config,
		pendingRosterChan: make(chan *rosterEdit),
		pendingSubscribes: make(map[string]string),
		lastActionTime:    time.Now(),
		// ignored contains UIDs that are currently being ignored.
		ignored:     make(map[string]struct{}),
		timeouts:    make(map[xmpp.Cookie]time.Time),
		uidComplete: new(PriorityList),
	}

	xio.SetSession(s)

	s.privateKey.Parse(config.PrivateKey)
	return
}

func (s *Session) Dial(addr, user, domain, password string, cfg *xmpp.Config) (err error) {

	if domain == "jabber.ccc.de" {
		// jabber.ccc.de uses CACert but distros are removing that root
		// certificate.
		roots := x509.NewCertPool()
		caCertRoot, err := x509.ParseCertificate(caroots.CaCertRootDER)
		if err == nil {
			s.Xio.Alert("Temporarily trusting only CACert root for CCC Jabber server")
			roots.AddCert(caCertRoot)
			cfg.TLSConfig.RootCAs = roots
		} else {
			s.Xio.Alert("Tried to add CACert root for jabber.ccc.de but failed: " + err.Error())
		}
	}

	s.Conn, err = xmpp.Dial(addr, user, domain, password, cfg)
	if err != nil {
		s.Xio.Alert("Failed to connect to XMPP server: " + err.Error())
		return
	}

	return
}

func (s *Session) FetchRoster() (err error) {

	s.Xio.Info("Fetching roster")

	//var rosterReply chan xmpp.Stanza
	s.rosterReply, _, err = s.RequestRoster()
	if err != nil {
		s.Xio.Alert("Failed to request roster: " + err.Error())
		return
	}

	return
}

func (s *Session) SetPromptForTarget(target string, isEncrypted bool) {
	s.lock.Lock()
	isCurrent := s.lastTarget == target
	s.lock.Unlock()

	if !isCurrent {
		return
	}

	s.Xio.SetPromptEnc(target, isEncrypted)
}

func (s *Session) SetLastTarget(lt string) {
	s.lastTarget = lt
}

func (s *Session) GetLastTarget() string {
	return s.lastTarget
}

func (s *Session) OptLastTarget(possibleName string) (ok bool) {
	ok = false
	s.lock.Lock()
	for _, uid := range s.uids {
		if possibleName == uid {
			s.lastTarget = possibleName
			ok = true
			break
		}
	}
	s.lock.Unlock()
	return
}

func (s *Session) Quit() {
	for to, conversation := range s.conversations {
		msgs := conversation.End()
		for _, msg := range msgs {
			s.Send(to, string(msg))
		}
	}
}

func (s *Session) GetRoster() []xmpp.RosterEntry {
	return s.roster
}

func (s *Session) GetState(jid string) (state string, ok bool) {
	state, ok = s.knownStates[jid]
	return
}

func (s *Session) GetVersion(user string) {
	replyChan, cookie, err := s.SendIQ(user, "get", xmpp.VersionQuery{})
	if err != nil {
		s.Xio.Alert("Error sending version request: " + err.Error())
		return
	}

	s.timeouts[cookie] = time.Now().Add(5 * time.Second)
	go s.awaitVersionReply(replyChan, user)
}

func (s *Session) DoEditRoster() {
	if s.pendingRosterEdit != nil {
		s.Xio.Warn("Aborting previous roster edit")
		s.pendingRosterEdit = nil
	}
	rosterCopy := make([]xmpp.RosterEntry, len(s.roster))
	copy(rosterCopy, s.roster)
	go s.EditRoster(rosterCopy)
}

func (s *Session) DoEditDoneRoster() {
	if s.pendingRosterEdit == nil {
		s.Xio.Warn("No roster edit in progress. Use /rosteredit to start one")
		return
	}
	go s.LoadEditedRoster(*s.pendingRosterEdit)
}

func (s *Session) ToggleStatusUpdates() {
	s.config.HideStatusUpdates = !s.config.HideStatusUpdates
	s.config.Save()
	// Tell the user the current state of the statuses
	if s.config.HideStatusUpdates {
		s.Xio.Info("Status updates disabled")
	} else {
		s.Xio.Info("Status updates enabled")
	}
}

func (s *Session) Msg(to string, msg string, encch chan<- bool) {
	conversation, ok := s.conversations[to]
	isEncrypted := ok && conversation.IsEncrypted()
	if encch != nil {
		encch <- isEncrypted
	}
	if !isEncrypted && s.config.ShouldEncryptTo(to) {
		s.Xio.Warn(fmt.Sprintf("Did not send: no encryption established with %s", to))
		return
	}
	var msgs [][]byte
	message := []byte(msg)
	// Automatically tag all outgoing plaintext
	// messages with a whitespace tag that
	// indicates that we support OTR.
	if s.config.OTRAutoAppendTag &&
		!bytes.Contains(message, []byte("?OTR")) &&
		(!ok || !conversation.IsEncrypted()) {
		message = append(message, OTRWhitespaceTag...)
	}
	if ok {
		var err error
		msgs, err = conversation.Send(message)
		if err != nil {
			s.Xio.Alert(err.Error())
			return
		}
	} else {
		msgs = [][]byte{[]byte(message)}
	}

	for _, message := range msgs {
		s.Send(to, string(message))
	}
}

func (s *Session) GetFingerprint() []byte {
	return s.privateKey.Fingerprint()
}

func (s *Session) EndConversation(to string) {
	conversation, ok := s.conversations[to]
	if !ok {
		s.Xio.Alert("No secure session established")
		return
	}
	msgs := conversation.End()
	for _, msg := range msgs {
		s.Send(to, string(msg))
	}
	s.SetPromptForTarget(to, false)
	s.Xio.Warn("OTR conversation ended with " + to)
}

func (s *Session) AuthQACommand(to, question, secret string) {
	conversation, ok := s.conversations[to]
	if !ok {
		s.Xio.Alert("Can't authenticate without a secure conversation established")
		return
	}
	msgs, err := conversation.Authenticate(question, []byte(secret))
	if err != nil {
		s.Xio.Alert("Error while starting authentication with " + to + ": " + err.Error())
	}
	for _, msg := range msgs {
		s.Send(to, string(msg))
	}
}

func (s *Session) tick(now time.Time) {
	haveExpired := false
	for _, expiry := range s.timeouts {
		if now.After(expiry) {
			haveExpired = true
			break
		}
	}
	if !haveExpired {
		return
	}

	newTimeouts := make(map[xmpp.Cookie]time.Time)
	for cookie, expiry := range s.timeouts {
		if now.After(expiry) {
			s.Cancel(cookie)
		} else {
			newTimeouts[cookie] = expiry
		}
	}
	s.timeouts = newTimeouts
}

func (s *Session) Handle() {
	stanzaChan := make(chan xmpp.Stanza)
	go s.ReadMessages(stanzaChan)

	ticker := time.NewTicker(1 * time.Second)

	running := true

	for running {
		select {
		case now := <-ticker.C:
			s.tick(now)

		case edit := <-s.pendingRosterChan:
			if !edit.isComplete {
				s.Xio.Info("Please edit " + edit.fileName + " and run /rostereditdone when complete")
				s.pendingRosterEdit = edit
				continue
			}
			if s.processEditedRoster(edit) {
				s.pendingRosterEdit = nil
			} else {
				s.Xio.Alert("Please reedit file and run /rostereditdone again")
			}

		case rosterStanza, ok := <-s.rosterReply:
			var err error
			if !ok {
				s.Xio.Alert("Failed to read roster")
				return
			}
			if s.roster, err = xmpp.ParseRoster(rosterStanza); err != nil {
				s.Xio.Alert("Failed to parse roster: " + err.Error())
				return
			}
			for _, entry := range s.roster {
				s.AddUser(entry.Jid)
			}
			s.Xio.Info("Roster received")

		case rawStanza, ok := <-stanzaChan:
			if !ok {
				s.Xio.Warn("Exiting because channel to server closed")
				running = false
				break
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
					s.Xio.Alert("Failed to send IQ message: " + err.Error())
				}

			case *xmpp.StreamError:
				var text string
				if len(stanza.Text) > 0 {
					text = stanza.Text
				} else {
					text = fmt.Sprintf("%s", stanza.Any)
				}
				s.Xio.Alert("Exiting in response to fatal error from server: " + text)
				running = false

			default:
				s.Xio.Info(fmt.Sprintf("%s %s", rawStanza.Name, rawStanza.Value))
			}
		}
	}
}

func (s *Session) PrintConversations() {
	for to, conversation := range s.conversations {
		if conversation.IsEncrypted() {
			s.Xio.Info(fmt.Sprintf("Secure session with %s underway:", to))
			s.PrintConversationInfo(to, conversation)
		}
	}
}

func (s *Session) AuthOOBCommand(to string, fingerprint string) {
	fpr, err := hex.DecodeString(fingerprint)
	if err != nil {
		s.Xio.Alert(fmt.Sprintf("Invalid fingerprint %s - not authenticated", fingerprint))
		return
	}
	existing := s.config.UserIdForFingerprint(fpr)
	if len(existing) != 0 {
		s.Xio.Alert(fmt.Sprintf("Fingerprint %s already belongs to %s", fingerprint, existing))
		return
	}
	s.config.KnownFingerprints = append(s.config.KnownFingerprints, KnownFingerprint{fingerprint: fpr, UserId: to})
	s.config.Save()
	s.Xio.Info(fmt.Sprintf("Saved manually verified fingerprint %s for %s", fingerprint, to))
}

func (s *Session) PrintConversationInfo(uid string, conversation *otr.Conversation) {
	fpr := conversation.TheirPublicKey.Fingerprint()
	fprUid := s.config.UserIdForFingerprint(fpr)
	s.Xio.Info(fmt.Sprintf("  Fingerprint  for %s: %x", uid, fpr))
	s.Xio.Info(fmt.Sprintf("  Session  ID  for %s: %x", uid, conversation.SSID))
	if fprUid == uid {
		s.Xio.Info(fmt.Sprintf("  Identity key for %s is verified", uid))
	} else if len(fprUid) > 1 {
		s.Xio.Alert(fmt.Sprintf("  Warning: %s is using an identity key which was verified for %s", uid, fprUid))
	} else if s.config.HasFingerprint(uid) {
		s.Xio.Critical(fmt.Sprintf("  Identity key for %s is incorrect", uid))
	} else {
		s.Xio.Alert(fmt.Sprintf("  Identity key for %s is not verified. You should use /otr-auth or /otr-authqa or /otr-authoob to verify their identity", uid))
	}
}
