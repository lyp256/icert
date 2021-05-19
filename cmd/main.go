package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/lyp256/icert/asset"
)

const (
	Year = time.Hour * 24 * 365
)

func main() {
	var (
		out             string
		rootCA, rootKey bool
		leafKeyFile     string
		leafKeyOut      string
		dns             []string
		ip              []net.IP
	)
	pflag.StringVarP(&out, "out", "o", "", "out file default print to stdout")
	pflag.StringVarP(&leafKeyFile, "leaf-key", "k", "", "private key default generate new key")
	pflag.StringVarP(&leafKeyOut, "leaf-key-out", "O", "", "new key out path")
	pflag.StringSliceVarP(&dns, "dns", "d", []string{}, "ca dns names")
	pflag.IPSliceVarP(&ip, "ip", "i", []net.IP{}, "ca ip address")
	pflag.BoolVarP(&rootCA, "root-ca", "C", false, "dump root ca")
	pflag.BoolVarP(&rootKey, "root-key", "K", false, "dump root key")

	pflag.Parse()
	if rootCA {
		err := outTo(out, asset.RootCABytes())
		if err != nil {
			log.Fatalln(err)
		}
		return
	}
	if rootKey {
		err := outTo(out, asset.RootKeyBytes())
		if err != nil {
			log.Fatalln(err)
		}
		return
	}
	var leafPubKey interface{}
	if leafKeyFile == "" {
		key := generateRSAKey(4096)
		leafPubKey = key.Public()
		err := saveKey(leafKeyFile, key)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		key, err := ParseKeyFile(leafKeyFile)
		if err != nil {
			log.Fatalf("parse key fail: %s", err)
		}
		k, ok := key.(interface {
			Public() crypto.PublicKey
		})
		if !ok {
			log.Fatalf("unsupport key %#v", key)
		}
		leafPubKey = k.Public()
	}
	b, err := generateCA(asset.RootCA(), asset.RootKey(), leafPubKey, dns, ip)
	if err != nil {
		log.Fatalln(err)
	}

	err = outTo(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
	if err != nil {
		log.Fatalln(err)
	}
}

func generateCA(rootCa *x509.Certificate, rootPri, leafPub interface{}, dns []string, ip []net.IP) ([]byte, error) {
	sn := big.NewInt(time.Now().UnixNano())
	leafCert := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"cert-test"},
			OrganizationalUnit: []string{"test"},
			SerialNumber:       sn.String(),
			CommonName:         "test-ca",
		},
		NotBefore:   time.Now().Add(-1 * Year),
		NotAfter:    time.Now().Add(1 * Year),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dns,
		IPAddresses: ip,
	}
	b, err := x509.CreateCertificate(random(), &leafCert, rootCa, leafPub, rootPri)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}
	return b, nil
}

func outTo(f string, content []byte) error {
	if f == "" {
		_, _ = os.Stdout.Write(content)
		return nil
	}

	file, err := os.Create(f)
	if err != nil {
		return fmt.Errorf("os.Create %s fail: %w", f, err)
	}
	_, _ = file.Write(content)
	return file.Close()
}
