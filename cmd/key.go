package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"time"
)

func random() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}

func generateEcdsaKey(c elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(c, random())
	if err != nil {
		panic(err)
	}
	return key
}

func generateEd25519Key(c elliptic.Curve) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, pri, err := ed25519.GenerateKey(random())
	if err != nil {
		panic(err)
	}
	return pub, pri
}

func generateRSAKey(n int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(random(), n)
	if err != nil {
		panic(err)
	}
	return key
}

func ParseKey(pemBytes []byte) (interface{}, error) {
	p, _ := pem.Decode(pemBytes)
	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey: %w", err)
	}
	return key, nil
}

func ParseKeyFile(file string) (interface{}, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile: %w", err)
	}
	return ParseKey(b)
}

func saveKey(f string, key interface{}) error {
	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("x509.MarshalPKCS8PrivateKey: %w", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyData})
	return outTo(f, b)
}
