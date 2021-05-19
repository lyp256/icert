package asset

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"log"
)

//go:embed rootCa.pem
var rootCAPemBytes []byte

//go:embed rootKey.pem
var rootKeyPemBytes []byte

func RootCABytes() []byte {
	b := make([]byte, len(rootCAPemBytes))
	copy(b, rootCAPemBytes)
	return b
}

func RootKeyBytes() []byte {
	b := make([]byte, len(rootKeyPemBytes))
	copy(b, rootKeyPemBytes)
	return b
}

func RootCA() *x509.Certificate {
	p, _ := pem.Decode(rootCAPemBytes)
	ca, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		log.Fatalf("x509.ParseCertificate:%s", err)
	}
	return ca
}

func RootKey() interface{} {
	p, _ := pem.Decode(rootKeyPemBytes)
	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		log.Fatalf("x509.ParsePKCS8PrivateKey:%s", err)
	}
	return key
}
