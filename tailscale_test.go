package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/libtailscale/tsnetctest"
	"golang.org/x/sys/unix"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func TestConn(t *testing.T) {
	tsnetctest.RunTestConn(t)

	// RunTestConn cleans up after itself, so there shouldn't be
	// anything left in the global maps.

	servers.mu.Lock()
	rem := len(servers.m)
	servers.mu.Unlock()

	if rem > 0 {
		t.Fatalf("want no remaining tsnet objects, got %d", rem)
	}

	var remConns, remLns int

	for i := 0; i < 50; i++ {
		conns.mu.Lock()
		remConns = len(conns.m)
		conns.mu.Unlock()

		listeners.mu.Lock()
		remLns = len(listeners.m)
		listeners.mu.Unlock()

		if remConns == 0 && remLns == 0 {
			break
		}

		// We are waiting for cleanup goroutines to finish.
		//
		// libtailscale closes one side of a socketpair and
		// then Go responds to the other side being unreadable
		// by closing the connections and listeners.
		//
		// This is inherently asynchronous.
		// Without ditching the standard close(2) and having our
		// own close functions.
		//
		// So we spin for a while
		time.Sleep(100 * time.Millisecond)
	}

	if remConns > 0 {
		t.Errorf("want no remaining tsnet_conn objects, got %d", remConns)
	}

	if remLns > 0 {
		t.Errorf("want no remaining tsnet_listener objects, got %d", remLns)
	}
}

// TestGetRemoteAddr checks that tailscale_getremoteaddr reports the
// right peer address for every accepted connection while fd numbers
// are being reused across connections (tailscale/tailscale#18310).
func TestGetRemoteAddr(t *testing.T) {
	tsnetctest.RunTestGetRemoteAddr(t)
}

// TestSocketpairCloexec checks that socketpair returns both ends
// close-on-exec, so that spawned processes cannot inherit the
// listener and connection fds.
func TestSocketpairCloexec(t *testing.T) {
	fds, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	for _, fd := range fds {
		flags, err := unix.FcntlInt(uintptr(fd), syscall.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flags&syscall.FD_CLOEXEC == 0 {
			t.Errorf("socketpair end %d is not close-on-exec", fd)
		}
	}
}

// TestRecvFdCloexec exercises the SCM_RIGHTS receive path TsnetAccept
// uses: an fd passed over the listener socketpair must be
// close-on-exec by the time it reaches C (via MSG_CMSG_CLOEXEC in
// recvFlags on Linux, via closeOnExec on platforms without it).
func TestRecvFdCloexec(t *testing.T) {
	sp, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(sp[0])
	defer syscall.Close(sp[1])

	// The fd we ship across the socketpair.
	pair, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(pair[0])
	defer syscall.Close(pair[1])

	var rec [listenAddrLen]byte
	copy(rec[:], "1.2.3.4")
	if err := syscall.Sendmsg(sp[0], rec[:], syscall.UnixRights(pair[0]), nil, 0); err != nil {
		t.Fatal(err)
	}

	data := make([]byte, listenAddrLen)
	cbuf := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := syscall.Recvmsg(sp[1], data, cbuf, recvFlags)
	if err != nil {
		t.Fatal(err)
	}
	if n != listenAddrLen {
		t.Fatalf("got %d bytes, want %d", n, listenAddrLen)
	}
	scms, err := syscall.ParseSocketControlMessage(cbuf[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	if len(scms) != 1 {
		t.Fatalf("got %d control messages, want 1", len(scms))
	}
	fds, err := syscall.ParseUnixRights(&scms[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(fds) != 1 {
		t.Fatalf("got %d fds, want 1", len(fds))
	}
	closeOnExec(fds[0]) // mirrors TsnetAccept
	defer syscall.Close(fds[0])

	flags, err := unix.FcntlInt(uintptr(fds[0]), syscall.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Errorf("fd received via SCM_RIGHTS is not close-on-exec")
	}
}

func TestExtractIP(t *testing.T) {
	ipv4 := "1.23.33.4:12343"
	ipv6 := "[1::2234::34fc::44]:56576"

	got4 := extractIP(ipv4)
	got6 := extractIP(ipv6)

	want4 := "1.23.33.4"
	want6 := "[1::2234::34fc::44]"

	if got4 != want4 {
		t.Errorf("ipv4 port stripping failed")
	}

	if got6 != want6 {
		t.Errorf("ipv6 port stripping failed %s != %s", got6, want6)
	}
}

// TestAcceptUnderLoad holds that every connection a listener accepts arrives
// open, with many connections coming in at once: 8 peers dial 20 connections
// each while the program takes each connection and says its line back.
//
// acceptLoop hands each accepted connection to the program as a descriptor in a
// record on the listener's socket pair, and until receive reads that record the
// message is the socket's only reference. On a Mac the collector of in-flight
// descriptors then takes such a socket and shuts it, and the program receives a
// connection that reads as closed before the peer's first byte: before the fix,
// 7 to 25 of these 160 connections arrived closed, run after run. Linux's
// collector does not take such a socket. One peer dialing at a time does not
// bring it out, so the connections have to come in at once.
//
// This drives the listener's own handoff, with a socket pair standing in for
// the end C holds; TestConn and TestGetRemoteAddr cover the same code end to
// end through the C API.
func TestAcceptUnderLoad(t *testing.T) {
	const dialers, each = 8, 20

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// The listener's socket pair: fds[0] is the program's end, and fds[1] is
	// the end acceptLoop sends on.
	fds, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	l := &listener{s: &server{s: &tsnet.Server{Logf: logger.Discard}}, ln: ln, fd: fds[1]}
	go l.acceptLoop(func() {})

	// The program's side: take each connection and say its line back.
	go func() {
		for {
			fd, _, err := l.receive(fds[0])
			if err != nil {
				return
			}
			go func() {
				f := os.NewFile(uintptr(fd), "connection")
				defer f.Close()
				line, err := bufio.NewReader(f).ReadString('\n')
				if err != nil {
					return
				}
				io.WriteString(f, line)
			}()
		}
	}()

	var lost atomic.Int64
	var dialing sync.WaitGroup
	for d := 0; d < dialers; d++ {
		dialing.Add(1)
		go func() {
			defer dialing.Done()
			for i := 0; i < each; i++ {
				said := fmt.Sprintf("connection %d.%d\n", d, i)
				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					lost.Add(1)
					continue
				}
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				io.WriteString(conn, said)
				heard, err := bufio.NewReader(conn).ReadString('\n')
				conn.Close()
				if err != nil || heard != said {
					lost.Add(1)
				}
			}
		}()
	}
	dialing.Wait()
	if n := lost.Load(); n != 0 {
		t.Fatalf("%d of %d connections arrived closed: each of them was shut while its descriptor was in flight", n, dialers*each)
	}
}
