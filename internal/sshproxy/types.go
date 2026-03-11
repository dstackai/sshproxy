package sshproxy

import (
	"context"

	"golang.org/x/crypto/ssh"
)

type Host struct {
	address    string
	user       string
	privateKey ssh.Signer
}

func NewHost(address string, user string, privateKey ssh.Signer) Host {
	return Host{
		address:    address,
		user:       user,
		privateKey: privateKey,
	}
}

type Upstream struct {
	hosts []Host
	// public keys data in SSH wire format as strings
	authorizedKeys map[string]struct{}
}

func NewUpstream(hosts []Host, authorizedKeys []ssh.PublicKey) Upstream {
	authKeys := make(map[string]struct{}, len(authorizedKeys))
	for _, authKey := range authorizedKeys {
		authKeys[string(authKey.Marshal())] = struct{}{}
	}

	return Upstream{
		hosts:          hosts,
		authorizedKeys: authKeys,
	}
}

func (u *Upstream) IsAuthorized(publicKey ssh.PublicKey) bool {
	_, ok := u.authorizedKeys[string(publicKey.Marshal())]

	return ok
}

// GetUpstreamCallback should return ErrUpstreamNotFound if upstream not found
// and any error value in case of other errors.
// The implementation should set reasonable timeouts for long-running operations,
// the caller side don't apply any timeout when calling the function.
type GetUpstreamCallback func(ctx context.Context, id string) (Upstream, error)
