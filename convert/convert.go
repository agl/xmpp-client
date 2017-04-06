package main

import (
	"bytes"
	"code.google.com/p/go.crypto/otr"
	"encoding/hex"
	"fmt"
	client "github.com/agl/xmpp-client"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

func ExportMPI(in string, mpi *big.Int) (out []byte) {
	out = []byte(fmt.Sprintf("  (%s #", in))
	enc := make([]byte, hex.EncodedLen(len(mpi.Bytes())))
	hex.Encode(enc, mpi.Bytes())
	out = append(out, bytes.ToUpper(enc)...)
	out = append(out, []byte("#)\n")...)
	return
}

func Export(priv otr.PrivateKey) (out []byte) {
	out = []byte("(private-key\n (dsa\n")
	out = append(out, ExportMPI("p", priv.PrivateKey.P)...)
	out = append(out, ExportMPI("q", priv.PrivateKey.Q)...)
	out = append(out, ExportMPI("g", priv.PrivateKey.G)...)
	out = append(out, ExportMPI("y", priv.PrivateKey.Y)...)
	out = append(out, ExportMPI("x", priv.PrivateKey.X)...)
	out = append(out, []byte("  )\n )")...)
	return
}

func main() {
	homeDir := os.Getenv("HOME")
	configFile := filepath.Join(homeDir, ".xmpp-client")
	config, err := client.ParseConfig(configFile)
	if err != nil {
		log.Fatal("Failed to parse config file: " + err.Error())
	}
	var priv otr.PrivateKey
	priv.Parse(config.PrivateKey)
	fmt.Println(string(Export(priv)))
}
