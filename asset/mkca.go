// +build ignore

//go:generate go run mkca.go

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

const (
	Year = time.Hour * 24 * 365
)

func main() {
	// pri, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pri, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("rsa.GenerateKey %s\n", err)
	}
	sn := big.NewInt(time.Now().UnixNano())
	rootCert := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"cert-test"},
			OrganizationalUnit: []string{"test"},
			SerialNumber:       sn.String(),
			CommonName:         "test-root-ca",
		},
		NotBefore: time.Now().Add(-10 * Year),
		NotAfter:  time.Now().Add(10 * Year),
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
	}
	data, err := x509.CreateCertificate(rand.Reader, &rootCert, &rootCert, pri.Public(), pri)
	if err != nil {
		log.Fatalf("x509.CreateCertificate %s\n", err)
	}
	{
		caFile, err := os.Create("rootCa.pem")
		if err != nil {
			log.Fatalf("create file rootCa.pem: %s\n", err)
		}
		err = pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: data})
		if err != nil {
			log.Fatalf("pem.Encode: %s\n", err)
		}
		_ = caFile.Close()
	}
	{
		keyData, err := x509.MarshalPKCS8PrivateKey(pri)
		if err != nil {
			log.Fatalf("x509.MarshalPKCS8PrivateKey: %s\n", err)
		}

		keyFile, err := os.Create("rootKey.pem")
		if err != nil {
			log.Fatalf("create file rootKey.pem: %s\n", err)
		}
		err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyData})
		if err != nil {
			log.Fatalf("pem.Encode: %s\n", err)
		}
		_ = keyFile.Close()
	}

}
