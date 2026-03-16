package sshproxy

import (
	"encoding/pem"
	"errors"
	"os"

	"golang.org/x/crypto/ssh"
)

var errNoPrivateKeys = errors.New("no private keys found")

type HostKey = ssh.Signer

func LoadHostKeysFromBlob(blob []byte) ([]HostKey, error) {
	var keys []HostKey
	var block *pem.Block
	rest := blob

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		key, err := ssh.ParsePrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, errNoPrivateKeys
	}

	return keys, nil
}

func LoadHostKeysFromFile(path string) ([]HostKey, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return LoadHostKeysFromBlob(blob)
}
