package xlib

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/agl/xmpp-client/xmpp"
	"golang.org/x/net/proxy"
	"io"
	"net/url"
	"strings"
)

func UserDom(account string) (user, domain string, err error) {
	parts := strings.SplitN(account, "@", 2)
	if len(parts) != 2 {
		err = errors.New("invalid username (want user@domain): " + account)
		return
	}
	user = parts[0]
	domain = parts[1]
	return
}

func Connect(xio XIO, config *Config, logger io.Writer, formcb xmpp.FormCallback) (s *Session, err error) {
	s = nil

	user, domain, err := UserDom(config.Account)
	if err != nil {
		return
	}

	var addr string
	addrTrusted := false

	if config.Server != "" && config.Port != 0 {
		addr = fmt.Sprintf("%s:%d", config.Server, config.Port)
		addrTrusted = true
	} else {
		if len(config.Proxies) > 0 {
			err = errors.New("Cannot connect via a proxy without Server and Port being set in the config file as an SRV lookup would leak information.")
			return
		}
		host := ""
		var port uint16
		host, port, err = xmpp.Resolve(domain)
		if err != nil {
			err = errors.New("Failed to resolve XMPP server: " + err.Error())
			return
		}
		addr = fmt.Sprintf("%s:%d", host, port)
	}

	var dialer proxy.Dialer
	for i := len(config.Proxies) - 1; i >= 0; i-- {
		var u *url.URL
		u, err = url.Parse(config.Proxies[i])
		if err != nil {
			err = errors.New("Failed to parse " + config.Proxies[i] + " as a URL: " + err.Error())
			return
		}
		if dialer == nil {
			dialer = proxy.Direct
		}
		if dialer, err = proxy.FromURL(u, dialer); err != nil {
			err = errors.New("Failed to parse " + config.Proxies[i] + " as a proxy: " + err.Error())
			return
		}
	}

	var certSHA256 []byte
	if len(config.ServerCertificateSHA256) > 0 {
		certSHA256, err = hex.DecodeString(config.ServerCertificateSHA256)
		if err != nil {
			err = errors.New("Failed to parse ServerCertificateSHA256 (should be hex string): " + err.Error())
			return
		}
		if len(certSHA256) != 32 {
			err = errors.New("ServerCertificateSHA256 is not 32 bytes long")
			return
		}
	}

	xmppConfig := &xmpp.Config{
		Log:                     logger,
		CreateCallback:          formcb,
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

	if len(config.RawLogFile) > 0 {
		err = SetupRawLog(config.RawLogFile, xmppConfig)
		if err != nil {
			err = errors.New("Failed to open raw log file: " + err.Error())
			return
		}
	}

	if dialer != nil {
		xio.Info("Making connection to " + addr + " via proxy")
		if xmppConfig.Conn, err = dialer.Dial("tcp", addr); err != nil {
			err = errors.New("Failed to connect via proxy: " + err.Error())
			return
		}
	}

	s = NewSession(config, xio)

	err = s.Dial(addr, user, domain, config.Password, xmppConfig)
	if err != nil {
		err = errors.New("Failed to connect to XMPP server: " + err.Error())
		return
	}

	return
}
