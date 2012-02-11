package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"exp/proxy"
	"exp/terminal"
	"github.com/agl/xmpp"
	"gocrypto.googlecode.com/git/otr"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
)

type Config struct {
	filename          string `json:"-"`
	Account           string
	Server            string   `json:",omitempty"`
	Proxies           []string `json:",omitempty"`
	Password          string   `json:",omitempty"`
	Port              int      `json:",omitempty"`
	PrivateKey        []byte
	KnownFingerprints []KnownFingerprint
	RawLogFile        string `json:",omitempty"`
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

func enroll(config *Config, term *terminal.Terminal) bool {
	var err error
	warn(term, "Enrolling new config file")

	var domain string
	for {
		term.SetPrompt("Account (i.e. user@example.com, enter to quit): ")
		if config.Account, err = term.ReadLine(); err != nil || len(config.Account) == 0 {
			return false
		}

		parts := strings.SplitN(config.Account, "@", 2)
		if len(parts) != 2 {
			alert(term, "invalid username (want user@domain): "+config.Account)
			continue
		}
		domain = parts[1]
		break
	}

	var proxyStr string
	term.SetPrompt("Proxy (i.e socks5://127.0.0.1:9050, enter for none): ")

	for {
		if proxyStr, err = term.ReadLine(); err != nil {
			return false
		}
		if len(proxyStr) == 0 {
			break
		}
		u, err := url.Parse(proxyStr)
		if err != nil {
			alert(term, "Failed to parse "+proxyStr+" as a URL: "+err.Error())
			continue
		}
		if _, err = proxy.FromURL(u, proxy.Direct); err != nil {
			alert(term, "Failed to parse "+proxyStr+" as a proxy: "+err.Error())
			continue
		}
		break
	}

	if len(proxyStr) > 0 {
		config.Proxies = []string{proxyStr}

		info(term, "Since you selected a proxy, we need to know the server and port to connect to as a SRV lookup would leak information every time.")
		term.SetPrompt("Server (i.e. xmpp.example.com, enter to lookup using unproxied DNS): ")
		if config.Server, err = term.ReadLine(); err != nil {
			return false
		}
		if len(config.Server) == 0 {
			var port uint16
			info(term, "Performing SRV lookup")
			if config.Server, port, err = xmpp.Resolve(domain); err != nil {
				alert(term, "SRV lookup failed: "+err.Error())
				return false
			}
			config.Port = int(port)
			info(term, "Resolved "+config.Server+":"+strconv.Itoa(config.Port))
		} else {
			for {
				term.SetPrompt("Port (enter for 5222): ")
				portStr, err := term.ReadLine()
				if err != nil {
					return false
				}
				if len(portStr) == 0 {
					portStr = "5222"
				}
				if config.Port, err = strconv.Atoi(portStr); err != nil || config.Port <= 0 || config.Port > 65535 {
					info(term, "Port numbers must be 0 < port <= 65535")
					continue
				}
				break
			}
		}
	}

	term.SetPrompt("File to import libotr private key from (enter to generate): ")

	var priv otr.PrivateKey
	for {
		importFile, err := term.ReadLine()
		if err != nil {
			return false
		}
		if len(importFile) > 0 {
			privKeyBytes, err := ioutil.ReadFile(importFile)
			if err != nil {
				alert(term, "Failed to open private key file: "+err.Error())
				continue
			}

			if !priv.Import(privKeyBytes) {
				alert(term, "Failed to parse libotr private key file (the parser is pretty simple I'm afraid)")
				continue
			}
			break
		} else {
			info(term, "Generating private key...")
			priv.Generate(rand.Reader)
			break
		}
	}
	config.PrivateKey = priv.Serialize(nil)

	term.SetPrompt("> ")

	return true
}
