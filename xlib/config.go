package xlib

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"

	"github.com/agl/xmpp-client/xmpp"
	"golang.org/x/crypto/otr"
	"golang.org/x/net/proxy"
)

type Config struct {
	filename                      string `json:"-"`
	Account                       string
	Server                        string   `json:",omitempty"`
	Proxies                       []string `json:",omitempty"`
	Password                      string   `json:",omitempty"`
	Port                          int      `json:",omitempty"`
	PrivateKey                    []byte
	KnownFingerprints             []KnownFingerprint
	RawLogFile                    string   `json:",omitempty"`
	NotifyCommand                 []string `json:",omitempty"`
	IdleSecondsBeforeNotification int      `json:",omitempty"`
	Bell                          bool
	HideStatusUpdates             bool
	UseTor                        bool
	OTRAutoTearDown               bool
	OTRAutoAppendTag              bool
	OTRAutoStartSession           bool
	ServerCertificateSHA256       string   `json:",omitempty"`
	AlwaysEncrypt                 bool     `json:",omitempty"`
	AlwaysEncryptWith             []string `json:",omitempty"`
}

type KnownFingerprint struct {
	UserId         string
	FingerprintHex string
	fingerprint    []byte `json:"-"`
}

func ParseConfig(filename string) (c *Config, err error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	c = new(Config)
	if err = json.Unmarshal(contents, &c); err != nil {
		return
	}

	c.filename = filename

	for i, known := range c.KnownFingerprints {
		c.KnownFingerprints[i].fingerprint, err = hex.DecodeString(known.FingerprintHex)
		if err != nil {
			err = errors.New("xmpp: failed to parse hex fingerprint for " + known.UserId + ": " + err.Error())
			return
		}
	}

	return
}

func (c *Config) Save() error {
	for i, known := range c.KnownFingerprints {
		c.KnownFingerprints[i].FingerprintHex = hex.EncodeToString(known.fingerprint)
	}

	contents, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(c.filename, contents, 0600)
}

func (c *Config) UserIdForFingerprint(fpr []byte) string {
	for _, known := range c.KnownFingerprints {
		if bytes.Equal(fpr, known.fingerprint) {
			return known.UserId
		}
	}

	return ""
}

func (c *Config) HasFingerprint(uid string) bool {
	for _, known := range c.KnownFingerprints {
		if uid == known.UserId {
			return true
		}
	}

	return false
}

func (c *Config) ShouldEncryptTo(uid string) bool {
	if c.AlwaysEncrypt {
		return true
	}

	for _, contact := range c.AlwaysEncryptWith {
		if contact == uid {
			return true
		}
	}
	return false
}

func NewConfig(filename string) (c *Config) {
	return &Config{filename: filename}
}

func isYes(s string) bool {
	lower := strings.ToLower(s)
	return lower == "yes" || lower == "y"
}

func Enroll(config *Config, xio XIO) bool {
	var err error
	xio.Warn("Enrolling new config file")

	var domain string
	for {
		xio.SetPrompt("Account (i.e. user@example.com, enter to quit): ")
		if config.Account, err = xio.ReadLine(); err != nil || len(config.Account) == 0 {
			return false
		}

		parts := strings.SplitN(config.Account, "@", 2)
		if len(parts) != 2 {
			xio.Alert("invalid username (want user@domain): " + config.Account)
			continue
		}
		domain = parts[1]
		break
	}

	const debugLogFile = "/tmp/xmpp-client-debug.log"
	xio.SetPrompt("Enable debug logging to " + debugLogFile + " (y/n)?: ")
	if debugLog, err := xio.ReadLine(); err != nil || !isYes(debugLog) {
		xio.Info("Not enabling debug logging...")
	} else {
		config.RawLogFile = debugLogFile
		xio.Info("Debug logging enabled.")
	}

	xio.SetPrompt("Use Tor (y/n)?: ")
	if useTorQuery, err := xio.ReadLine(); err != nil || !isYes(useTorQuery) {
		xio.Info("Not using Tor...")
		config.UseTor = false
	} else {
		xio.Info("Using Tor...")
		config.UseTor = true
	}

	xio.SetPrompt("File to import libotr private key from (enter to generate): ")

	var priv otr.PrivateKey
	for {
		importFile, err := xio.ReadLine()
		if err != nil {
			return false
		}
		if len(importFile) > 0 {
			privKeyBytes, err := ioutil.ReadFile(importFile)
			if err != nil {
				xio.Alert("Failed to open private key file: " + err.Error())
				continue
			}

			if !priv.Import(privKeyBytes) {
				xio.Alert("Failed to parse libotr private key file (the parser is pretty simple I'm afraid)")
				continue
			}
			break
		} else {
			xio.Info("Generating private key...")
			priv.Generate(rand.Reader)
			break
		}
	}
	config.PrivateKey = priv.Serialize(nil)

	config.OTRAutoAppendTag = true
	config.OTRAutoStartSession = true
	config.OTRAutoTearDown = false

	// List well known Tor hidden services.
	knownTorDomain := map[string]string{
		"jabber.ccc.de":             "okj7xc6j2szr2y75.onion",
		"riseup.net":                "4cjw6cwpeaeppfqz.onion",
		"jabber.calyxinstitute.org": "ijeeynrc6x2uy5ob.onion",
		"jabber.otr.im":             "5rgdtlawqkcplz75.onion",
		"wtfismyip.com":             "ofkztxcohimx34la.onion",
		"rows.io":                   "yz6yiv2hxyagvwy6.onion",
	}

	// Autoconfigure well known Tor hidden services.
	if hiddenService, ok := knownTorDomain[domain]; ok && config.UseTor {
		const torProxyURL = "socks5://127.0.0.1:9050"
		xio.Info("It appears that you are using a well known server and we will use its Tor hidden service to connect.")
		config.Server = hiddenService
		config.Port = 5222
		config.Proxies = []string{torProxyURL}
		xio.SetPrompt("> ")
		return true
	}

	var proxyStr string
	proxyDefaultPrompt := ", enter for none"
	if config.UseTor {
		proxyDefaultPrompt = ", which is the default"
	}
	xio.SetPrompt("Proxy (i.e socks5://127.0.0.1:9050" + proxyDefaultPrompt + "): ")

	for {
		if proxyStr, err = xio.ReadLine(); err != nil {
			return false
		}
		if len(proxyStr) == 0 {
			if !config.UseTor {
				break
			} else {
				proxyStr = "socks5://127.0.0.1:9050"
			}
		}
		u, err := url.Parse(proxyStr)
		if err != nil {
			xio.Alert("Failed to parse " + proxyStr + " as a URL: " + err.Error())
			continue
		}
		if _, err = proxy.FromURL(u, proxy.Direct); err != nil {
			xio.Alert("Failed to parse " + proxyStr + " as a proxy: " + err.Error())
			continue
		}
		break
	}

	if len(proxyStr) > 0 {
		config.Proxies = []string{proxyStr}

		xio.Info("Since you selected a proxy, we need to know the server and port to connect to as a SRV lookup would leak information every time.")
		xio.SetPrompt("Server (i.e. xmpp.example.com, enter to lookup using unproxied DNS): ")
		if config.Server, err = xio.ReadLine(); err != nil {
			return false
		}
		if len(config.Server) == 0 {
			var port uint16
			xio.Info("Performing SRV lookup")
			if config.Server, port, err = xmpp.Resolve(domain); err != nil {
				xio.Alert("SRV lookup failed: " + err.Error())
				return false
			}
			config.Port = int(port)
			xio.Info("Resolved " + config.Server + ":" + strconv.Itoa(config.Port))
		} else {
			for {
				xio.SetPrompt("Port (enter for 5222): ")
				portStr, err := xio.ReadLine()
				if err != nil {
					return false
				}
				if len(portStr) == 0 {
					portStr = "5222"
				}
				if config.Port, err = strconv.Atoi(portStr); err != nil || config.Port <= 0 || config.Port > 65535 {
					xio.Info("Port numbers must be 0 < port <= 65535")
					continue
				}
				break
			}
		}
	}

	xio.SetPrompt("> ")

	return true
}
