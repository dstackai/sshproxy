package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
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

type Server struct {
	address string

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
		ServerVersion: serverVersion,
	}

	for _, key := range hostKeys {
		logger.WithField("type", key.PublicKey().Type()).Debug("host key added")
		config.AddHostKey(key)
	}

	server := Server{
		address:       net.JoinHostPort(address, strconv.Itoa(port)),
		getUpstream:   getUpstream,
		upstreamCache: ttlcache.NewCache[string, Upstream](upstreamCacheTTL),
		config:        config,
		conns:         make(map[net.Conn]struct{}),
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
			handleConnection(log.WithLogger(ctx, logger), conn, s.config)
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
	upstreamID := conn.User()
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

func handleConnection(ctx context.Context, conn net.Conn, config *ssh.ServerConfig) {
	logger := log.GetLogger(ctx)

	defer func() {
		err := conn.Close()
		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to close connection")
		}
	}()

	clientConn, clientNewChans, clientReqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		handleConnectionError(ctx, err)
		return
	}

	logger.Debug("client logged in")

	upstream := clientConn.Permissions.ExtraData[upstreamExtraDataKey].(Upstream)
	upstreamConn, upstreamNewChans, upstreamReqs, err := connectToUpstream(ctx, upstream)
	if err != nil {
		logger.WithError(err).Error("failed to connect to upstream")

		return
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		bridgeGlobalRequests(ctx, clientToUpstream, clientReqs, upstreamConn)
		// <-chan *Request (and <-chan NewChannel) is closed when an error is encountered,
		// including closed connection, see x/crypto/ssh/mux.go, mux.loop()
		// We close the upstream connection here to interrupt goroutines
		// spawned by bridgeNewChannels -> handleChannel that io.Copy() stdout/stderr,
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
		bridgeNewChannels(ctx, clientToUpstream, clientNewChans, upstreamConn)
	})
	wg.Go(func() {
		bridgeGlobalRequests(ctx, upstreamToClient, upstreamReqs, clientConn)

		err := clientConn.Close()
		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to close client connection")
		} else {
			logger.Debug("client connection closed")
		}
	})
	wg.Go(func() {
		bridgeNewChannels(ctx, upstreamToClient, upstreamNewChans, clientConn)
	})
	wg.Wait()
}

func handleConnectionError(ctx context.Context, err error) {
	logger := log.GetLogger(ctx)

	if isClosedError(err) {
		return
	}

	authErr, isAuthErr := errors.AsType[*ssh.ServerAuthError](err)
	if !isAuthErr {
		logger.WithError(err).Error("failed to handshake client")
		return
	}

	for _, err := range authErr.Errors {
		if errors.Is(err, ErrUpstreamNotFound) {
			logger.Debug("client requested unknown upstream")
			return
		}
	}

	logger.WithError(err).Debug("client auth failed")
}

func connectToUpstream(
	ctx context.Context,
	upstream Upstream,
) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	var conn ssh.Conn
	var chans <-chan ssh.NewChannel
	var reqs <-chan *ssh.Request

	for i, host := range upstream.hosts {
		config := &ssh.ClientConfig{
			User: host.user,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(host.privateKey),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		var netConn net.Conn
		var err error

		if i == 0 {
			d := net.Dialer{
				Timeout: upstreamDialTimeout,
			}
			netConn, err = d.DialContext(ctx, "tcp", host.address)
		} else {
			client := ssh.NewClient(conn, chans, reqs)
			// TODO: Is it possible to specify timeout?
			netConn, err = client.Dial("tcp", host.address)
		}

		if err != nil {
			return nil, nil, nil, fmt.Errorf("dial upstream %d %s: %w", i, host.address, err)
		}

		conn, chans, reqs, err = ssh.NewClientConn(netConn, host.address, config)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create SSH connection %d %s: %w", i, host.address, err)
		}
	}

	return conn, chans, reqs, nil
}

func bridgeGlobalRequests(ctx context.Context, dir direction, inReqs <-chan *ssh.Request, outConn ssh.Conn) {
	logger := log.GetLogger(ctx).WithField("dir", dir)
	for req := range inReqs {
		logger := logger.WithField("type", req.Type)
		logger.Trace("global request")

		reply, payload, err := outConn.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(reply, payload)
		}

		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to forward global request")
		}
	}
}

func bridgeNewChannels(ctx context.Context, dir direction, inNewChans <-chan ssh.NewChannel, outConn ssh.Conn) {
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
		bridgeChannelRequests(ctx, dir.reverse(), outReqs, inChan)
	})

	var inWg sync.WaitGroup

	inWg.Go(func() {
		_, _ = io.Copy(outChan, inChan)
		_ = outChan.CloseWrite()
	})
	inWg.Go(func() {
		bridgeChannelRequests(ctx, dir, inReqs, outChan)
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

func bridgeChannelRequests(ctx context.Context, dir direction, inReqs <-chan *ssh.Request, outConn ssh.Channel) {
	logger := log.GetLogger(ctx).WithField("dir", dir)
	for req := range inReqs {
		logger := logger.WithField("type", req.Type)
		logger.Trace("request")

		reply, err := outConn.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(reply, nil)
		}

		if err != nil && !isClosedError(err) {
			logger.WithError(err).Error("failed to forward channel request")
		}
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}
