package sshproxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// getNegotiatedHostKeyAlgorithm returns the host key algorithm agreed during key exchange, or an empty
// string if it cannot be determined. The accessor is not part of the exported ssh.Conn interface,
// so it is reached via a type assertion against the concrete connection.
func getNegotiatedHostKeyAlgorithm(conn ssh.Conn) string {
	type algorithmsProvider interface {
		Algorithms() ssh.NegotiatedAlgorithms
	}
	switch c := conn.(type) {
	case algorithmsProvider:
		return c.Algorithms().HostKey
	case *ssh.ServerConn:
		if provider, ok := c.Conn.(algorithmsProvider); ok {
			return provider.Algorithms().HostKey
		}
	}
	return ""
}

// appendSSHString appends s to buf using the SSH "string" wire encoding (a uint32 length prefix
// followed by the raw bytes).
func appendSSHString(buf, s []byte) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	return append(buf, s...)
}

// parseSSHString reads one SSH "string" from the front of buf, returning it along with the
// remaining bytes. ok is false if buf is truncated.
func parseSSHString(buf []byte) (value, rest []byte, ok bool) {
	if len(buf) < 4 {
		return nil, buf, false
	}
	length := binary.BigEndian.Uint32(buf)
	buf = buf[4:]
	if uint32(len(buf)) < length {
		return nil, buf, false
	}
	return buf[:length], buf[length:], true
}

func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}

func getSSHError(err error) error {
	for {
		if strings.HasPrefix(err.Error(), "ssh: ") {
			return err
		}
		err = errors.Unwrap(err)
		if err == nil {
			break
		}
	}

	return nil
}

func isClientAuthFailureError(err error) bool {
	sshErr := getSSHError(err)
	if sshErr == nil {
		return false
	}
	// https://github.com/golang/crypto/blob/982eaa62dfb7273603b97fc1835561450096f3bd/ssh/client_auth.go#L118
	return strings.Contains(sshErr.Error(), "unable to authenticate")
}
