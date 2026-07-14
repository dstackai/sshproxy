package sshproxy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dstackai/sshproxy/internal/log"
	"github.com/dstackai/sshproxy/internal/ttlcache"
)

var serverVersion = "SSH-2.0-dstack_sshproxy_" + Version

const (
	upstreamCacheTTL             = time.Second * 10
	upstreamCacheCleanupInterval = time.Minute * 5
	upstreamExtraDataKey         = "upstream"
	upstreamDialTimeout          = time.Second * 10
)

// allowed* algorithms are closely copied from the OpenSSH_10.0p2 Ubuntu-5ubuntu5.1 default config.
// ssh.SupportedAlgorithms() returns almost the same, but the order slightly differs and some items are missing.
// It was decided to explicitly list all algos instead of using library-provided defaults.
// As a consequence, the lists must be periodically checked against the current version of OpenSSH
// and updated if necessary.

var allowedKeyExchanges = []string{
	ssh.KeyExchangeMLKEM768X25519,
	ssh.KeyExchangeCurve25519,
	ssh.KeyExchangeECDHP256,
	ssh.KeyExchangeECDHP384,
	ssh.KeyExchangeECDHP521,
}

var allowedCiphers = []string{
	ssh.CipherChaCha20Poly1305,
	ssh.CipherAES128GCM,
	ssh.CipherAES256GCM,
	ssh.CipherAES128CTR,
	ssh.CipherAES192CTR,
	ssh.CipherAES256CTR,
}

var allowedMACs = []string{
	ssh.HMACSHA256ETM,
	ssh.HMACSHA512ETM,
	ssh.HMACSHA256,
	ssh.HMACSHA512,
	ssh.HMACSHA1,
}

var allowedPublicKeyAuthAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

var allowedHostKeyAlgorithms = []string{
	ssh.CertAlgoED25519v01,
	ssh.CertAlgoECDSA256v01,
	ssh.CertAlgoECDSA384v01,
	ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoSKED25519v01,
	ssh.CertAlgoSKECDSA256v01,
	ssh.CertAlgoRSASHA512v01,
	ssh.CertAlgoRSASHA256v01,
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

// Global request names for the host key update mechanism for SSH:
// https://datatracker.ietf.org/doc/draft-ietf-sshm-hostkey-update/
// The "-00@openssh.com" variants are the ones currently sent and understood by OpenSSH; the bare
// names are the standardized ones the draft is moving towards.
const (
	hostKeysRequest             = "hostkeys"
	hostKeysRequestOpenSSH      = "hostkeys-00@openssh.com"
	hostKeysProveRequest        = "hostkeys-prove"
	hostKeysProveRequestOpenSSH = "hostkeys-prove-00@openssh.com"
	// hostKeysProvePreambleStd is a value of the first field of the structure signed for the standardized
	// "hostkeys-prove" request. For the vendor-specific request the request name itself is used as the field's value.
	hostKeysProvePreambleStd = "hostkeys-prove-0"
)

var blacklistedUpstreamToClientGlobalRequests = []string{
	// Host keys advertised by the upstream running inside the job container are irrelevant to the client since
	// our proxy is _not_ transparent -- the client connection is terminated on the proxy's side, the only keys used
	// for KEX are our keys.
	hostKeysRequest,
	hostKeysRequestOpenSSH,
}

type direction string

var (
	clientToUpstream direction = direction("C-U")
	upstreamToClient direction = direction("U-C")
)

func (d direction) reverse() direction {
	if d == clientToUpstream {
		return upstreamToClient
	}

	return clientToUpstream
}

var ErrUpstreamNotFound = errors.New("upstream not found")

var (
	errServerClosed     = errors.New("server closed")
	errUnknownPublicKey = errors.New("unknown public key")
)

// upstreamAuthFailureError represents an SSH client auth failure (that is, SSH_MSG_USERAUTH_FAILURE) when connecting
// to any host in the Upstream.hosts chain (either a jump host or a target host)
type upstreamAuthFailureError struct {
	sshErr       error
	isTargetHost bool
}

func (e *upstreamAuthFailureError) Error() string {
	return fmt.Sprintf("auth failure: %s", e.sshErr.Error())
}

func (e *upstreamAuthFailureError) Unwrap() error {
	return e.sshErr
}

type Server struct {
	address string

	hostPublicKeyBlobs     [][]byte
	hostPublicKeyBlobToKey map[string]HostKey

	getUpstream   GetUpstreamCallback
	upstreamCache *ttlcache.Cache[string, Upstream]

	config   *ssh.ServerConfig
	listener net.Listener
	serveCtx context.Context

	inShutdown atomic.Bool
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	connsWg    sync.WaitGroup
}

func NewServer(
	ctx context.Context, address string, port int,
	hostKeys []HostKey, getUpstream GetUpstreamCallback,
) *Server {
	logger := log.GetLogger(ctx)
	config := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: allowedKeyExchanges,
			Ciphers:      allowedCiphers,
			MACs:         allowedMACs,
		},
		PublicKeyAuthAlgorithms: allowedPublicKeyAuthAlgorithms,
		ServerVersion:           serverVersion,
	}

	publicKeyBlobs := make([][]byte, 0, len(hostKeys))
	publicKeyBlobToKey := make(map[string]HostKey, len(hostKeys))
	keyTypesSeen := make(map[string]struct{})
	for _, key := range hostKeys {
		publicKey := key.PublicKey()
		keyType := publicKey.Type()
		logger := logger.WithField("type", keyType).WithField("fp", ssh.FingerprintSHA256(publicKey))
		publicKeyBlob := publicKey.Marshal()
		if _, seen := publicKeyBlobToKey[string(publicKeyBlob)]; !seen {
			if _, seen := keyTypesSeen[keyType]; !seen {
				config.AddHostKey(key)
				logger.Debug("host key added for KEX and advertisement")
				keyTypesSeen[keyType] = struct{}{}
			} else {
				logger.Debug("host key added for advertisement only")
			}
			publicKeyBlobs = append(publicKeyBlobs, publicKeyBlob)
			publicKeyBlobToKey[string(publicKeyBlob)] = key
		} else {
			logger.Debug("duplicate host key skipped")
		}
	}

	server := Server{
		address:                net.JoinHostPort(address, strconv.Itoa(port)),
		hostPublicKeyBlobToKey: publicKeyBlobToKey,
		hostPublicKeyBlobs:     publicKeyBlobs,
		getUpstream:            getUpstream,
		upstreamCache:          ttlcache.NewCache[string, Upstream](upstreamCacheTTL),
		config:                 config,
		conns:                  make(map[net.Conn]struct{}),
	}
	server.config.PublicKeyCallback = server.publicKeyCallback

	return &server
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.inShutdown.Load() {
		return errServerClosed
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", s.address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.address, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.serveCtx = ctx
	s.mu.Unlock()

	logger := log.GetLogger(ctx)
	logger.WithField("address", s.address).Info("listening for client connections")

	_ = s.upstreamCache.StartCleanup(upstreamCacheCleanupInterval)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.inShutdown.Load() {
				return nil
			}

			logger.WithError(err).Error("failed to accept incoming connection")
			continue
		}

		logger := logger.WithField("client", conn.RemoteAddr().String())

		s.addConnection(conn)
		s.connsWg.Go(func() {
			s.handleConnection(log.WithLogger(ctx, logger), conn)
			s.removeConnection(conn)
		})
	}
}

func (s *Server) Close(ctx context.Context) error {
	s.inShutdown.Store(true)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener == nil {
		return errServerClosed
	}

	logger := log.GetLogger(ctx)
	logger.Info("closing listener and connections")

	err := s.listener.Close()

	for conn := range s.conns {
		_ = conn.Close()
		delete(s.conns, conn)
	}

	s.mu.Unlock()
	s.connsWg.Wait()
	s.mu.Lock()

	_ = s.upstreamCache.StopCleanup()

	return err
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, publicKey ssh.PublicKey) (*ssh.Permissions, error) {
	upstreamID, _ := parseAuthUser(conn.User())
	logger := log.GetLogger(s.serveCtx).WithField("id", upstreamID)

	upstream, found := s.upstreamCache.Get(upstreamID)
	if !found {
		var err error
		upstream, err = s.getUpstream(s.serveCtx, upstreamID)
		if err != nil {
			if errors.Is(err, ErrUpstreamNotFound) {
				logger.Debug("upstream not found")
			} else {
				logger.WithError(err).Error("failed to get upstream")
			}
			return nil, fmt.Errorf("get upstream: %w", err)
		}

		s.upstreamCache.Set(upstreamID, upstream)
		logger.Trace("got upstream")
	} else {
		logger.Trace("using cached upstream")
	}

	if upstream.IsAuthorized(publicKey) {
		return &ssh.Permissions{
			ExtraData: map[any]any{
				upstreamExtraDataKey: upstream,
			},
		}, nil
	}

	return nil, errUnknownPublicKey
}

func (s *Server) addConnection(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.conns[conn] = struct{}{}
}

func (s *Server) removeConnection(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.conns, conn)
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	logger := log.GetLogger(ctx)

	defer func() {
		err := conn.Close()
		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to close connection")
		}
	}()

	clientConn, clientNewChans, clientReqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		handleConnectionError(ctx, err)
		return
	}

	logger.Debug("client logged in")

	upstream := clientConn.Permissions.ExtraData[upstreamExtraDataKey].(Upstream)
	_, user := parseAuthUser(clientConn.User())
	upstreamConn, upstreamNewChans, upstreamReqs, err := connectToUpstream(ctx, upstream, user)
	if err != nil {
		logger = logger.WithError(err)
		if user != "" {
			logger = logger.WithField("user", user)
		}

		const msg = "failed to connect to upstream"
		// Don't log as an error if it is a client auth error on the last host in the chain and the user is overridden
		// to avoid log noise in case a non-existent user is requested
		if authErr, ok := errors.AsType[*upstreamAuthFailureError](err); ok && authErr.isTargetHost && user != "" {
			logger.Debug(msg)
		} else {
			logger.Error(msg)
		}

		return
	}

	// Advertise our host keys now that the upstream is connected and we are about to start servicing
	// the client's global requests, so the client's hostkeys-prove round-trip is answered promptly.
	// Failure is non-fatal: it only means the client connection is broken, which the handlers below
	// detect and tear down.
	if err := advertiseHostKeys(ctx, clientConn, s.hostPublicKeyBlobs); err != nil {
		logger.WithError(err).Error("failed to advertise host keys")
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		handleClientToUpstreamGlobalRequests(ctx, clientReqs, clientConn, upstreamConn, s.hostPublicKeyBlobToKey)
		// <-chan *Request (and <-chan NewChannel) is closed when an error is encountered,
		// including closed connection, see x/crypto/ssh/mux.go, mux.loop()
		// We close the upstream connection here to interrupt goroutines
		// spawned by handleNewChannels -> handleChannel that io.Copy() stdout/stderr,
		// otherwise they may stuck trying to read from a Channel, as Channel.Read()
		// doesn't fail after sending Channel.Close()
		err := upstreamConn.Close()
		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to close upstream connection")
		} else {
			logger.Debug("upstream connection closed")
		}
	})
	wg.Go(func() {
		handleNewChannels(ctx, clientToUpstream, clientNewChans, upstreamConn)
	})
	wg.Go(func() {
		handleUpstreamToClientGlobalRequests(ctx, upstreamReqs, clientConn)

		err := clientConn.Close()
		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to close client connection")
		} else {
			logger.Debug("client connection closed")
		}
	})
	wg.Go(func() {
		handleNewChannels(ctx, upstreamToClient, upstreamNewChans, clientConn)
	})
	wg.Wait()
}

func handleConnectionError(ctx context.Context, err error) {
	logger := log.GetLogger(ctx)

	if isClosedError(err) {
		return
	}

	if errors.Is(err, syscall.ECONNRESET) {
		// For example, OpenSSH client may send RST during key exchange if the host keys have changed
		logger.WithError(err).Debug("connection reset by client")
		return
	}

	if errors.Is(err, syscall.ETIMEDOUT) {
		logger.WithError(err).Debug("client connection timed out")
		return
	}

	if authErr, ok := errors.AsType[*ssh.ServerAuthError](err); ok {
		for _, err := range authErr.Errors {
			if errors.Is(err, ErrUpstreamNotFound) {
				logger.Debug("client requested unknown upstream")
				return
			}
		}

		logger.WithError(err).Debug("client auth failed")
		return
	}

	if algoErr, ok := errors.AsType[*ssh.AlgorithmNegotiationError](err); ok {
		logger.WithField("offered", algoErr.RequestedAlgorithms).Debugf("no common algorithm for %s", algoErr.What)
		return
	}

	if sshErr := getSSHError(err); sshErr != nil {
		errMsg := sshErr.Error()

		for _, msg := range [...]string{
			// https://github.com/golang/crypto/blob/982eaa62dfb7273603b97fc1835561450096f3bd/ssh/transport.go#L369
			"overflow reading version string",
			// https://github.com/golang/crypto/blob/982eaa62dfb7273603b97fc1835561450096f3bd/ssh/messages.go#L385
			// e.g., "unmarshal error for field Language of type disconnectMsg"
			"unmarshal error",
			// https://github.com/golang/crypto/blob/982eaa62dfb7273603b97fc1835561450096f3bd/ssh/common.go#L382
			"unexpected message type",
			// https://github.com/golang/crypto/blob/982eaa62dfb7273603b97fc1835561450096f3bd/ssh/common.go#L387
			// All errors collected in the wild are about `SSH_MSG_USERAUTH_REQUEST` (50), see `serverAuthenticate()`:
			// https://github.com/golang/crypto/blob/982eaa62dfb7273603b97fc1835561450096f3bd/ssh/server.go#L530
			// but we suppress all such errors as any malformed message is suspicious, esp. during authentication
			"parse error in message type",
		} {
			if strings.Contains(errMsg, msg) {
				logger.WithError(err).Debug("suspicious client")
				return
			}
		}

		// https://github.com/golang/crypto/blob/982eaa62dfb7273603b97fc1835561450096f3bd/ssh/messages.go#L47
		// e.g., "ssh: disconnect, reason 11: disconnected by user"
		// Most probably this is also a suspicious client, but may be a legitimate use of SSH_MSG_DISCONNECT
		if strings.Contains(errMsg, "disconnect, reason") {
			logger.WithError(err).Debug("client disconnected")
			return
		}
	}

	logger.WithError(err).Error("failed to handshake client")
}

// parseAuthUser extracts upstreamID and optional upstreamUser (overrides the default upstream user)
// from the "user name" field of the SSH_MSG_USERAUTH_REQUEST request (the `user` in the `ssh user@hostname` command)
// The optional user is appended to the upstreamID after the `_` delimiter:
// 3b07781fc52d4427b3f4e83f16abb104@ssh.dstack.example.com - log in as the default job user
// 3b07781fc52d4427b3f4e83f16abb104_root@ssh.dstack.example.com - log in as `root`
func parseAuthUser(user string) (upstreamID string, upstreamUser string) {
	upstreamID, upstreamUser, _ = strings.Cut(user, "_")
	return upstreamID, upstreamUser
}

func connectToUpstream(
	ctx context.Context, upstream Upstream, user string,
) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	logger := log.GetLogger(ctx)

	var conn ssh.Conn
	var chans <-chan ssh.NewChannel
	var reqs <-chan *ssh.Request

	// A target host is the last host in the Upstream.hosts chanin. All other hosts are jump hosts.
	targetHostIdx := len(upstream.hosts) - 1
	for hostIdx, host := range upstream.hosts {
		isTargetHost := hostIdx == targetHostIdx
		hostUser := host.user
		if isTargetHost && user != "" {
			hostUser = user
		}
		config := &ssh.ClientConfig{
			Config: ssh.Config{
				KeyExchanges: allowedKeyExchanges,
				Ciphers:      allowedCiphers,
				MACs:         allowedMACs,
			},
			User: hostUser,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(host.privateKey),
			},
			HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
			HostKeyAlgorithms: allowedHostKeyAlgorithms,
		}

		var netConn net.Conn
		var err error

		if hostIdx == 0 {
			d := net.Dialer{
				Timeout: upstreamDialTimeout,
			}
			netConn, err = d.DialContext(ctx, "tcp", host.address)
		} else {
			client := ssh.NewClient(conn, chans, reqs)
			// TODO: Is it possible to specify timeout?
			netConn, err = client.Dial("tcp", host.address)
		}

		var hostType string
		if isTargetHost {
			hostType = "target"
		} else {
			hostType = "jump"
		}

		if err != nil {
			return nil, nil, nil, fmt.Errorf("dial %s host #%d %s: %w", hostType, hostIdx, host.address, err)
		}

		conn, chans, reqs, err = ssh.NewClientConn(netConn, host.address, config)
		if err != nil {
			if isClientAuthFailureError(err) {
				err = &upstreamAuthFailureError{
					sshErr:       err,
					isTargetHost: isTargetHost,
				}
			}

			return nil, nil, nil, fmt.Errorf(
				"create SSH connection to %s host #%d %s: %w", hostType, hostIdx, host.address, err)
		}

		logger.Tracef("connected to %s host #%d %s", hostType, hostIdx, host.address)
	}

	return conn, chans, reqs, nil
}

func handleClientToUpstreamGlobalRequests(
	ctx context.Context,
	inReqs <-chan *ssh.Request,
	inConn ssh.Conn,
	outConn ssh.Conn,
	hostKeys map[string]HostKey,
) {
	logger := log.GetLogger(ctx).WithField("dir", clientToUpstream)
	for req := range inReqs {
		logger := logger.WithField("type", req.Type)
		if req.Type == hostKeysProveRequest || req.Type == hostKeysProveRequestOpenSSH {
			logger.Trace("hostkeys-prove global request")
			err := proveHostKeys(ctx, req, inConn, hostKeys)
			if err != nil && !isClosedError(err) {
				logger.WithError(err).Error("failed to handle hostkeys-prove global request")
			}
		} else {
			forwardGlobalRequest(log.WithLogger(ctx, logger), req, outConn)
		}
	}
}

func handleUpstreamToClientGlobalRequests(ctx context.Context, inReqs <-chan *ssh.Request, outConn ssh.Conn) {
	logger := log.GetLogger(ctx).WithField("dir", upstreamToClient)
	for req := range inReqs {
		logger := logger.WithField("type", req.Type)
		if slices.Contains(blacklistedUpstreamToClientGlobalRequests, req.Type) {
			logger.Trace("blacklisted global request, ignoring")
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		} else {
			forwardGlobalRequest(log.WithLogger(ctx, logger), req, outConn)
		}
	}
}

func forwardGlobalRequest(ctx context.Context, req *ssh.Request, outConn ssh.Conn) {
	logger := log.GetLogger(ctx)
	logger.Trace("global request")
	ok, payload, err := outConn.SendRequest(req.Type, req.WantReply, req.Payload)
	if req.WantReply {
		_ = req.Reply(ok, payload)
	}

	if err != nil && !isClosedError(err) {
		logger.WithError(err).Error("failed to forward global request")
	}
}

func handleNewChannels(ctx context.Context, dir direction, inNewChans <-chan ssh.NewChannel, outConn ssh.Conn) {
	logger := log.GetLogger(ctx)

	var wg sync.WaitGroup

	for inNewChan := range inNewChans {
		logger := logger.WithField("chan", inNewChan.ChannelType())
		logger.WithField("dir", dir).Trace("new channel requested")
		wg.Go(func() {
			handleChannel(log.WithLogger(ctx, logger), dir, inNewChan, outConn)
		})
	}

	wg.Wait()

	logger.WithField("dir", dir).Trace("channels done")
}

func handleChannel(ctx context.Context, dir direction, inNewChan ssh.NewChannel, outConn ssh.Conn) {
	logger := log.GetLogger(ctx)

	outChan, outReqs, err := outConn.OpenChannel(inNewChan.ChannelType(), inNewChan.ExtraData())
	if err != nil {
		// Trace level to avoid spamming in case of rejected port forwarding
		logger.WithError(err).Trace("new channel rejected by the other side")
		_ = inNewChan.Reject(ssh.ConnectionFailed, err.Error())

		return
	}

	inChan, inReqs, err := inNewChan.Accept()
	if err != nil {
		if !isClosedError(err) {
			logger.WithError(err).Error("failed to accept new channel")
		}

		_ = outChan.Close()

		return
	}

	logger.Trace("new channel accepted")

	var outWg sync.WaitGroup

	outWg.Go(func() {
		_, _ = io.Copy(inChan, outChan)
		_ = inChan.CloseWrite()
	})
	outWg.Go(func() {
		_, _ = io.Copy(inChan.Stderr(), outChan.Stderr())
	})
	outWg.Go(func() {
		handleChannelRequests(ctx, dir.reverse(), outReqs, inChan)
	})

	var inWg sync.WaitGroup

	inWg.Go(func() {
		_, _ = io.Copy(outChan, inChan)
		_ = outChan.CloseWrite()
	})
	inWg.Go(func() {
		handleChannelRequests(ctx, dir, inReqs, outChan)
	})

	var wg sync.WaitGroup

	wg.Go(func() {
		outWg.Wait()

		_ = inChan.Close()
	})
	wg.Go(func() {
		inWg.Wait()

		_ = outChan.Close()
	})
	wg.Wait()

	logger.Trace("channel done")
}

func handleChannelRequests(ctx context.Context, dir direction, inReqs <-chan *ssh.Request, outConn ssh.Channel) {
	logger := log.GetLogger(ctx).WithField("dir", dir)
	for req := range inReqs {
		logger := logger.WithField("type", req.Type)
		logger.Trace("request")

		ok, err := outConn.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}

		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to forward channel request")
		}
	}
}

// advertiseHostKeys informs the client of the full set of host keys served by the proxy using the "hostkeys" global
// request of the host key update mechanism. This lets clients learn newly added keys (and prune retired ones) for
// zero-downtime host key rotation. It must be called once, after the client has authenticated.
// hostPublicKeyBlobs is expected to be non-empty and free of duplicates.
func advertiseHostKeys(ctx context.Context, conn ssh.Conn, hostPublicKeyBlobs [][]byte) error {
	var payload []byte
	for _, blob := range hostPublicKeyBlobs {
		payload = appendSSHString(payload, blob)
	}

	// want_reply is false: the advertisement is fire-and-forget. The client follows up with a
	// separate hostkeys-prove request for the subset of keys it wants us to prove ownership of.
	if _, _, err := conn.SendRequest(hostKeysRequestOpenSSH, false, payload); err != nil {
		return fmt.Errorf("send %s request: %w", hostKeysRequestOpenSSH, err)
	}

	log.GetLogger(ctx).WithField("count", len(hostPublicKeyBlobs)).Debug("advertised host keys")
	return nil
}

// proveHostKeys answers a client's "hostkeys-prove" request by signing, with each requested host
// key, a proof that binds the key to this session. The client uses these proofs to safely add newly
// advertised keys to its known_hosts. The reply is a signature per requested key, in request order.
func proveHostKeys(ctx context.Context, req *ssh.Request, conn ssh.Conn, hostKeys map[string]HostKey) error {
	// For RSA host keys the proof must use a signature algorithm compatible with the one negotiated
	// during key exchange; other key types have a single native algorithm. See OpenSSH's
	// server_input_hostkeys_prove() and draft-ietf-sshm-hostkey-update.
	kexRSASigAlgo := rsaKEXSignatureAlgorithm(conn)
	if kexRSASigAlgo == ssh.KeyAlgoRSA {
		// ssh-rsa (RSA-SHA1) was negotiated during key exchange. The draft mandates failing the
		// request rather than emitting an insecure SHA-1 proof; the client keeps its known_hosts
		// as is and simply misses this round of rotation.
		_ = req.Reply(false, nil)
		return errors.New("refusing hostkeys-prove: insecure ssh-rsa negotiated during key exchange")
	}

	preamble := hostKeysProvePreambleStd
	if req.Type == hostKeysProveRequestOpenSSH {
		preamble = hostKeysProveRequestOpenSSH
	}

	sessionID := conn.SessionID()

	var reply []byte
	proven := 0
	payload := req.Payload
	for len(payload) > 0 {
		blob, rest, ok := parseSSHString(payload)
		if !ok {
			_ = req.Reply(false, nil)
			return errors.New("malformed hostkeys-prove payload")
		}
		payload = rest

		signer, found := hostKeys[string(blob)]
		if !found {
			// The client asked us to prove ownership of a key we don't serve.
			_ = req.Reply(false, nil)
			return fmt.Errorf("proof requested for unknown host key %s", blob)
		}

		signData := marshalHostKeyProof(preamble, sessionID, blob)
		sig, err := signHostKeyProof(signer, signData, kexRSASigAlgo)
		if err != nil {
			_ = req.Reply(false, nil)
			return fmt.Errorf("sign host key proof: %w", err)
		}
		reply = appendSSHString(reply, ssh.Marshal(sig))
		proven++
	}

	if err := req.Reply(true, reply); err != nil {
		return fmt.Errorf("reply to %s request: %w", req.Type, err)
	}

	log.GetLogger(ctx).WithField("count", proven).Trace("proved host keys")
	return nil
}

// rsaKEXSignatureAlgorithm returns the host key algorithm negotiated during key exchange if it is
// an RSA algorithm, otherwise an empty string.
func rsaKEXSignatureAlgorithm(conn ssh.Conn) string {
	switch algo := getNegotiatedHostKeyAlgorithm(conn); algo {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return algo
	default:
		return ""
	}
}

// signHostKeyProof signs the host key proof structure with signer. RSA keys use kexRSASigAlgo when
// an RSA key was negotiated during key exchange, otherwise rsa-sha2-512; they never sign with the
// insecure ssh-rsa (SHA-1) default returned by Signer.Sign. Other key types sign natively.
func signHostKeyProof(signer HostKey, data []byte, kexRSASigAlgo string) (*ssh.Signature, error) {
	if signer.PublicKey().Type() != ssh.KeyAlgoRSA {
		return signer.Sign(rand.Reader, data)
	}

	algo := kexRSASigAlgo
	if algo == "" {
		algo = ssh.KeyAlgoRSASHA512
	}
	algoSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("RSA host key of type %T does not implement ssh.AlgorithmSigner", signer)
	}
	return algoSigner.SignWithAlgorithm(rand.Reader, data, algo)
}

// marshalHostKeyProof builds the structure signed for a single host key proof:
//
//	string    preamble ("hostkeys-prove-0" or "hostkeys-prove-00@openssh.com")
//	string    session identifier
//	string    host key blob
func marshalHostKeyProof(preamble string, sessionID, hostKey []byte) []byte {
	var buf []byte
	buf = appendSSHString(buf, []byte(preamble))
	buf = appendSSHString(buf, sessionID)
	buf = appendSSHString(buf, hostKey)
	return buf
}
