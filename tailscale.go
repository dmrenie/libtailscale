// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// A Go c-archive of the tsnet package. See tailscale.h for details.
package main

//#include "errno.h"
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func main() {}

// servers tracks all the allocated *tsnet.Server objects.
var servers struct {
	mu   sync.Mutex
	next C.int
	m    map[C.int]*server
}

type server struct {
	s       *tsnet.Server
	lastErr string
	started bool
}

func getServer(sd C.int) *server {
	servers.mu.Lock()
	defer servers.mu.Unlock()
	return servers.m[sd]
}

// listeners tracks all the tsnet_listener objects allocated via tsnet_listen.
var listeners struct {
	mu sync.Mutex
	m  map[C.int]*listener
}

type listener struct {
	s  *server
	ln net.Listener
	fd int // go side fd of socketpair sent to C
	mu sync.Mutex
	// m maps the fd number C holds for an accepted connection (not our
	// sender-side number; recvmsg installs a new one) to its remote IP.
	m map[C.int]string
	// inFlight holds the sender's descriptors in record order. On macOS an
	// accepted socket can arrive closed if its only reference is in a queued
	// SCM_RIGHTS message. Keep the sender's reference until receipt.
	inFlight []int
	// recvMu makes reading a record and closing the head of inFlight one step,
	// so that the head is always the record that the caller read, even when C
	// calls tailscale_accept from more than one thread.
	recvMu sync.Mutex
}

// listenAddrLen is the size of the fixed-size, NUL-padded record that
// carries each accepted connection's remote IP over the listener
// socketpair. Fixed size so TsnetAccept reads exactly one
// record at a time; 45 bytes covers the longest textual IP.
const listenAddrLen = 64

// conns tracks all the pipe(2)s allocated via tsnet_dial.
var conns struct {
	mu sync.Mutex
	m  map[C.int]*conn // keyed by the FD given to C (w)
}

type conn struct {
	s *tsnet.Server
	c net.Conn
	r *os.File // r is the local socket to the C client
}

func (s *server) recErr(err error) C.int {
	if err == nil {
		s.lastErr = ""
		return 0
	}
	s.lastErr = err.Error()
	return -1
}

//export TsnetNewServer
func TsnetNewServer() C.int {
	servers.mu.Lock()
	defer servers.mu.Unlock()

	if servers.m == nil {
		servers.m = map[C.int]*server{}
		hostinfo.SetApp("libtailscale")
	}
	if servers.next == 0 {
		servers.next = 42<<16 + 1
	}
	sd := servers.next
	servers.next++
	s := &server{s: &tsnet.Server{}}
	servers.m[sd] = s
	return (C.int)(sd)
}

//export TsnetStart
func TsnetStart(sd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	err := s.s.Start()
	if err == nil {
		s.started = true
	}
	return s.recErr(err)
}

//export TsnetUp
func TsnetUp(sd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	_, err := s.s.Up(context.Background()) // cancellation is via TsnetClose
	if err == nil {
		s.started = true
	}
	return s.recErr(err)
}

//export TsnetClose
func TsnetClose(sd C.int) C.int {
	servers.mu.Lock()
	s := servers.m[sd]
	if s != nil {
		delete(servers.m, sd)
	}
	servers.mu.Unlock()

	if s == nil {
		return C.EBADF
	}

	// TODO: cancel Up
	// TODO: close related listeners / conns.
	if !s.started {
		// Server was never started, nothing to close.
		return 0
	}
	if err := s.s.Close(); err != nil {
		s.s.Logf("tailscale_close: failed with %v", err)
		return -1
	}

	return 0
}

//export TsnetGetIps
func TsnetGetIps(sd C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}

	servers.mu.Lock()
	s := servers.m[sd]
	servers.mu.Unlock()

	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)

	if s == nil {
		out[0] = '\x00'
		return C.EBADF
	}

	ip4, ip6 := s.s.TailscaleIPs()
	joined := strings.Join([]string{ip4.String(), ip6.String()}, ",")
	n := copy(out, joined)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

//export TsnetErrmsg
func TsnetErrmsg(sd C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}

	servers.mu.Lock()
	s := servers.m[sd]
	servers.mu.Unlock()

	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)
	if s == nil {
		out[0] = '\x00'
		return C.EBADF
	}
	n := copy(out, s.lastErr)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

//export TsnetListen
func TsnetListen(sd C.int, network, addr *C.char, listenerOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	ln, err := s.s.Listen(C.GoString(network), C.GoString(addr))
	if err != nil {
		return s.recErr(err)
	}
	s.started = true

	// The tailscale_listener we return to C is one side of a socketpair(2).
	// We do this so we can proactively call ln.Accept in a goroutine and
	// feed an fd for the connection through the listener. This lets C use
	// epoll on the tailscale_listener to know if it should call
	// tailscale_accept, which avoids a blocking call on the far side.
	// Both ends are close-on-exec, so spawned processes do not inherit
	// them.
	fds, err := socketpair()
	if err != nil {
		return s.recErr(err)
	}
	sp := fds[1]
	fdC := C.int(fds[0])

	listeners.mu.Lock()
	if listeners.m == nil {
		listeners.m = map[C.int]*listener{}
	}
	listener := &listener{s: s, ln: ln, fd: sp, m: map[C.int]string{}}
	listeners.m[fdC] = listener
	listeners.mu.Unlock()

	go func() {
		listener.serve()
		listeners.mu.Lock()
		if listeners.m[fdC] == listener {
			delete(listeners.m, fdC)
		}
		listeners.mu.Unlock()
	}()

	*listenerOut = fdC
	return 0
}

// serve owns the sending socket. Neither the watcher nor a concurrent
// accept may close it while the sender is using it.
func (l *listener) serve() {
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		// C never writes to the listener. EOF means its end was closed.
		var buf [1]byte
		for {
			if _, err := syscall.Read(l.fd, buf[:]); err != syscall.EINTR {
				break
			}
		}
		syscall.Shutdown(l.fd, syscall.SHUT_WR) // wake a blocked send without closing its fd
		l.ln.Close()                            // wake Accept
	}()

	l.acceptLoop()
	// Accept can also end first (e.g. when the server stops). Wake the
	// watcher without recycling its fd while it may still be in Read.
	syscall.Shutdown(l.fd, syscall.SHUT_RDWR)
	<-watchDone
	syscall.Close(l.fd)
	l.mu.Lock()
	for _, fd := range l.inFlight {
		syscall.Close(fd)
	}
	l.inFlight = nil
	l.mu.Unlock()
}

func (l *listener) acceptLoop() {
	for {
		netConn, err := l.ln.Accept()
		if err != nil {
			return
		}
		var connFd C.int
		if err := newConn(l.s, netConn, &connFd); err != nil {
			if l.s.s.Logf != nil {
				l.s.s.Logf("libtailscale.accept: newConn: %v", err)
			}
			netConn.Close()
			continue
		}
		ip := extractIP(netConn.RemoteAddr().String())
		if len(ip) >= listenAddrLen {
			if l.s.s.Logf != nil {
				l.s.s.Logf("libtailscale.accept: remote address %q does not fit in a %d-byte record", ip, listenAddrLen)
			}
			netConn.Close()
			syscall.Close(int(connFd))
			continue
		}
		var addrRec [listenAddrLen]byte
		copy(addrRec[:], ip)

		l.mu.Lock()
		l.inFlight = append(l.inFlight, int(connFd))
		l.mu.Unlock()

		rights := syscall.UnixRights(int(connFd))
		err = syscall.Sendmsg(l.fd, addrRec[:], rights, nil, 0)
		if err != nil {
			// a failed sendmsg delivered nothing (sp being closed is
			// handled by the read goroutine above)
			if l.s.s.Logf != nil {
				l.s.s.Logf("libtailscale.accept: sendmsg failed: %v", err)
			}
			netConn.Close()
			// Only this goroutine appends. The unsent fd is the tail;
			// receivers can only have removed earlier entries.
			l.mu.Lock()
			l.inFlight = l.inFlight[:len(l.inFlight)-1]
			l.mu.Unlock()
			syscall.Close(int(connFd))
		}
		// On success, receive closes our copy once C holds its own.
	}
}

//export TsnetAccept
func TsnetAccept(listenerFd C.int, connOut *C.int) C.int {
	listeners.mu.Lock()
	ln := listeners.m[listenerFd]
	listeners.mu.Unlock()

	if ln == nil {
		return C.EBADF
	}

	fd, addr, err := ln.receive(int(listenerFd))
	if err != nil {
		return ln.s.recErr(err)
	}

	// the entry must exist before C can learn this fd number
	ln.mu.Lock()
	ln.m[fd] = addr
	ln.mu.Unlock()

	*connOut = fd

	return 0
}

// receive reads one record from the listener's socket pair, listenerFd, and
// returns the descriptor that the kernel installed for it, which C then holds,
// and the remote address that came in the record.
//
// One record per connection: the fd via SCM_RIGHTS plus its remote IP. The fd
// returned is the number the kernel installed, i.e. the number C will hold, and
// it is close-on-exec (via recvFlags on Linux, or the closeOnExec call below
// elsewhere).
//
// Serialize the entire record, not just the queue update: a stream read
// can end between the byte carrying SCM_RIGHTS and the rest of the address.
func (l *listener) receive(listenerFd int) (C.int, string, error) {
	l.recvMu.Lock()
	defer l.recvMu.Unlock()

	var data [listenAddrLen]byte
	cbuf := make([]byte, unix.CmsgSpace(int(unsafe.Sizeof(C.int(0)))))
	var n, oobn int
	for {
		var err error
		n, oobn, _, _, err = syscall.Recvmsg(listenerFd, data[:], cbuf, recvFlags)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, "", err
		}
		if n == 0 {
			return 0, "", io.EOF
		}
		break
	}
	scms, err := syscall.ParseSocketControlMessage(cbuf[:oobn])
	if err != nil {
		return 0, "", err
	}
	if len(scms) != 1 {
		return 0, "", fmt.Errorf("libtailscale: got %d control messages, want 1", len(scms))
	}
	fds, err := syscall.ParseUnixRights(&scms[0])
	if err != nil {
		return 0, "", err
	}
	if len(fds) != 1 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return 0, "", fmt.Errorf("libtailscale: got %d FDs, want 1", len(fds))
	}
	fd := fds[0]
	closeOnExec(fd)
	for n < len(data) {
		nn, err := syscall.Read(listenerFd, data[n:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil || nn == 0 {
			syscall.Close(fd)
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return 0, "", err
		}
		n += nn
	}
	l.mu.Lock()
	if len(l.inFlight) > 0 { // serve may already have drained it at shutdown
		syscall.Close(l.inFlight[0])
		l.inFlight = l.inFlight[1:]
	}
	l.mu.Unlock()

	addrLen := bytes.IndexByte(data[:], 0)
	if addrLen < 0 {
		addrLen = listenAddrLen
	}
	return C.int(fd), string(data[:addrLen]), nil
}

func newConn(s *server, netConn net.Conn, connOut *C.int) error {
	fds, err := socketpair()
	if err != nil {
		return err
	}
	r := os.NewFile(uintptr(fds[1]), "socketpair-r")
	c := &conn{s: s.s, c: netConn, r: r}
	fdC := C.int(fds[0])

	conns.mu.Lock()
	if conns.m == nil {
		conns.m = make(map[C.int]*conn)
	}
	conns.m[fdC] = c
	conns.mu.Unlock()

	connCleanup := func() {
		var inCleanup bool
		conns.mu.Lock()
		if tsConn, ok := conns.m[fdC]; ok && tsConn.c == netConn {
			delete(conns.m, fdC)
			inCleanup = true
		}
		conns.mu.Unlock()

		if !inCleanup {
			return
		}

		r.Close()
		netConn.Close()
	}
	// the Shutdowns below must precede connCleanup: r.Fd() after Close
	// can return a reused fd number. Wait for both copy directions.
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		var b [1 << 16]byte
		io.CopyBuffer(r, netConn, b[:])
		syscall.Shutdown(int(r.Fd()), syscall.SHUT_WR)
		if cr, ok := netConn.(interface{ CloseRead() error }); ok {
			cr.CloseRead()
		}
	}()
	go func() {
		defer copies.Done()
		var b [1 << 16]byte
		io.CopyBuffer(netConn, r, b[:])
		syscall.Shutdown(int(r.Fd()), syscall.SHUT_RD)
		if cw, ok := netConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		copies.Wait()
		connCleanup()
	}()

	*connOut = fdC
	return nil
}

//export TsnetGetRemoteAddr
func TsnetGetRemoteAddr(listener C.int, conn C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)

	listeners.mu.Lock()
	defer listeners.mu.Unlock()
	l := listeners.m[listener]
	if l == nil {
		out[0] = '\x00'
		return C.EBADF
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	ip, ok := l.m[conn]
	if !ok {
		// set errmsg too: EBADF with an empty message is not debuggable
		l.s.lastErr = fmt.Sprintf("libtailscale: getremoteaddr: no remote address recorded for conn %d on listener %d", conn, listener)
		out[0] = '\x00'
		return C.EBADF
	}

	n := copy(out, ip)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

// Strips the port from connection IPs
func extractIP(ipWithPort string) string {
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[([0-9a-fA-F:]+)\]`)
	match := re.FindString(ipWithPort)
	return match
}

//export TsnetDial
func TsnetDial(sd C.int, network, addr *C.char, connOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	netConn, err := s.s.Dial(context.Background(), C.GoString(network), C.GoString(addr))
	if err != nil {
		return s.recErr(err)
	}
	s.started = true
	if err := newConn(s, netConn, connOut); err != nil {
		return s.recErr(err)
	}
	return 0
}

//export TsnetSetDir
func TsnetSetDir(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.Dir = C.GoString(str)
	return 0
}

//export TsnetSetHostname
func TsnetSetHostname(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.Hostname = C.GoString(str)
	return 0
}

//export TsnetSetAuthKey
func TsnetSetAuthKey(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.AuthKey = C.GoString(str)
	return 0
}

//export TsnetSetControlURL
func TsnetSetControlURL(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.ControlURL = C.GoString(str)
	return 0
}

//export TsnetSetEphemeral
func TsnetSetEphemeral(sd C.int, e int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if e == 0 {
		s.s.Ephemeral = false
	} else {
		s.s.Ephemeral = true
	}
	return 0
}

//export TsnetSetLogFD
func TsnetSetLogFD(sd, fd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if fd == -1 {
		s.s.Logf = logger.Discard
		return 0
	}
	f := os.NewFile(uintptr(fd), "logfd")
	s.s.Logf = func(format string, args ...any) {
		fmt.Fprintf(f, format, args...)
		fmt.Fprintf(f, "\n")
	}
	return 0
}

//export TsnetLoopback
func TsnetLoopback(sd C.int, addrOut *C.char, addrLen C.size_t, proxyOut *C.char, localOut *C.char) C.int {
	// Panic here to ensure we always leave the out values NUL-terminated.
	if addrOut == nil {
		panic("loopback_api passed nil addr_out")
	} else if addrLen == 0 {
		panic("loopback_api passed addrlen of 0")
	} else if proxyOut == nil {
		panic("loopback_api passed nil proxy_cred_out")
	} else if localOut == nil {
		panic("loopback_api passed nil local_api_cred_out")
	}

	// Start out NUL-termianted to cover error conditions.
	*addrOut = '\x00'
	*localOut = '\x00'
	*proxyOut = '\x00'

	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	addr, proxyCred, localAPICred, err := s.s.Loopback()
	if err != nil {
		return s.recErr(err)
	}
	if len(proxyCred) != 32 {
		return s.recErr(fmt.Errorf("libtailscale: len(proxyCred)=%d, want 32", len(proxyCred)))
	}
	if len(localAPICred) != 32 {
		return s.recErr(fmt.Errorf("libtailscale: len(localAPICred)=%d, want 32", len(localAPICred)))
	}

	out := unsafe.Slice((*byte)(unsafe.Pointer(addrOut)), addrLen)
	n := copy(out, addr)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'

	// proxyOut and localOut are non-nil and 33 bytes long because
	// they are defined in C as char cred_out[static 33].
	out = unsafe.Slice((*byte)(unsafe.Pointer(proxyOut)), 33)
	copy(out, proxyCred)
	out[32] = '\x00'
	out = unsafe.Slice((*byte)(unsafe.Pointer(localOut)), 33)
	copy(out, localAPICred)
	out[32] = '\x00'

	return 0
}

//export TsnetStatusJSON
func TsnetStatusJSON(sd C.int, jsonOut **C.char) C.int {
	if jsonOut == nil {
		panic("status_json passed nil json_out")
	}
	*jsonOut = nil
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	// LocalClient rides tsnet's in-memory LocalAPI listener — unlike
	// Loopback()'s TCP listener it cannot be reclaimed by the OS while
	// the process is suspended (iOS), so status reads keep working on
	// long-lived nodes.
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := lc.Status(ctx)
	if err != nil {
		return s.recErr(err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return s.recErr(err)
	}
	*jsonOut = C.CString(string(b))
	return 0
}

//export TsnetEnableFunnelToLocalhostPlaintextHttp1
func TsnetEnableFunnelToLocalhostPlaintextHttp1(sd C.int, localhostPort C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	ctx := context.Background()
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}

	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return s.recErr(err)
	}
	domain := st.CertDomains[0]

	hp := ipn.HostPort(net.JoinHostPort(domain, strconv.Itoa(443)))
	tcpForward := fmt.Sprintf("127.0.0.1:%d", localhostPort)
	sc := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443: {
				TCPForward:   tcpForward,
				TerminateTLS: domain,
			},
		},
		AllowFunnel: map[ipn.HostPort]bool{
			hp: true,
		},
	}

	lc.SetServeConfig(ctx, sc)
	if !sc.AllowFunnel[hp] {
		return s.recErr(fmt.Errorf("libtailscale: failed to enable funnel"))
	}

	return 0
}
