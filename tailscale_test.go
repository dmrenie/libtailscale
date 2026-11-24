package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
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

// startListener runs the production handoff using a local TCP listener.
func startListener(t *testing.T) (*listener, int, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := socketpair()
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	l := &listener{s: &server{s: &tsnet.Server{Logf: logger.Discard}}, ln: ln, fd: pair[1]}
	done := make(chan struct{})
	go func() {
		l.serve()
		close(done)
	}()
	return l, pair[0], done
}

func TestAcceptUnderLoad(t *testing.T) {
	l, program, done := startListener(t)
	var receivers sync.WaitGroup
	for range 2 {
		receivers.Go(func() {
			for {
				fd, _, err := l.receive(program)
				if err == io.EOF {
					return
				}
				if err != nil {
					t.Errorf("receive descriptor: %v", err)
					return
				}
				f := os.NewFile(uintptr(fd), "accepted connection")
				line, err := bufio.NewReader(f).ReadString('\n')
				if err != nil {
					t.Errorf("accepted connection: read %d bytes before %v", len(line), err)
				} else if _, err := io.WriteString(f, line); err != nil {
					t.Errorf("accepted connection: write echo: %v", err)
				}
				f.Close()
			}
		})
	}
	defer func() {
		syscall.Shutdown(program, syscall.SHUT_RDWR)
		receivers.Wait()
		<-done
		syscall.Close(program)
	}()

	var clients sync.WaitGroup
	for d := range 8 {
		clients.Go(func() {
			for i := range 20 {
				conn, err := net.DialTimeout("tcp", l.ln.Addr().String(), 5*time.Second)
				if err != nil {
					t.Errorf("client %d.%d dial: %v", d, i, err)
					return
				}
				line := fmt.Sprintf("connection %d.%d\n", d, i)
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Error(err)
				} else if _, err := io.WriteString(conn, line); err != nil {
					t.Errorf("write %q: %v", line, err)
				} else if got, err := bufio.NewReader(conn).ReadString('\n'); err != nil || got != line {
					t.Errorf("echo for %q: got %q, err=%v", line, got, err)
				}
				conn.Close()
			}
		})
	}
	clients.Wait()
}

// Wait for bytes to arrive (or be consumed) without consuming the SCM_RIGHTS.
func waitReadable(t *testing.T, fd int, want bool) {
	t.Helper()
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		_, err := unix.Poll(poll, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || poll[0].Revents&^unix.POLLIN != 0 {
			t.Fatalf("poll: revents=%#x err=%v", poll[0].Revents, err)
		}
		if (poll[0].Revents != 0) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for readability=%v", want)
}

// A readable listener with no accept means the socket owns a queued record.
// Closing it must stop the sender and release the unclaimed connection.
func TestCloseWithPendingHandoff(t *testing.T) {
	l, program, done := startListener(t)
	defer func() {
		if program >= 0 {
			syscall.Close(program)
		}
	}()
	peer, err := net.Dial("tcp", l.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	waitReadable(t, program, true)
	syscall.Close(program)
	program = -1
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not exit after listener close")
	}
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("unclaimed connection after shutdown: got %v, want EOF", err)
	}
}

// The rights travel with the first byte, not with the rest of the record.
func TestReceiveSplitRecord(t *testing.T) {
	pair, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(pair[0])
	defer syscall.Close(pair[1])
	l := new(listener)
	var readers sync.WaitGroup
	var rec [listenAddrLen]byte
	for _, name := range []string{"first", "second"} {
		data, err := socketpair()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { syscall.Close(data[0]); syscall.Close(data[1]) })
		if _, err := syscall.Write(data[0], []byte{name[0]}); err != nil {
			t.Fatal(err)
		}
		clear(rec[:])
		copy(rec[:], name)
		if err := syscall.Sendmsg(pair[1], rec[:1], syscall.UnixRights(data[1]), nil, 0); err != nil {
			t.Fatal(err)
		}
		if name == "first" {
			for range 2 {
				readers.Go(func() {
					fd, addr, err := l.receive(pair[0])
					if err != nil {
						t.Errorf("receive split record: %v", err)
						return
					}
					defer syscall.Close(int(fd))
					var tag [1]byte
					n, err := syscall.Read(int(fd), tag[:])
					if err != nil || n != 1 || (addr != "first" && addr != "second") || tag[0] != addr[0] {
						t.Errorf("split record: address=%q tag=%q n=%d err=%v", addr, tag, n, err)
					}
				})
			}
			defer func() {
				syscall.Shutdown(pair[1], syscall.SHUT_WR)
				readers.Wait()
			}()
			// Don't write the tail until the first recvmsg has consumed its byte.
			waitReadable(t, pair[0], false)
		}
		if n, err := syscall.Write(pair[1], rec[1:]); n != len(rec)-1 || err != nil {
			t.Fatalf("write record tail: n=%d err=%v", n, err)
		}
	}
}
