package asset

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootKey(t *testing.T) {
	key := RootKey()
	_, ok := key.(*rsa.PrivateKey)
	require.True(t, ok)
}

func TestRootCA(t *testing.T) {
	ca := RootCA()
	require.NotNil(t, ca)
}
