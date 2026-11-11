package remote

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSOCKS accepts one connection, records the requested destination,
// and echoes after the handshake. reply4 sets the SOCKS4 reply code.
func fakeSOCKS(t *testing.T, reply4 byte) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		ver, _ := r.ReadByte()
		switch ver {
		case 4:
			var h [7]byte
			io.ReadFull(r, h[:])
			user, _ := r.ReadString(0)
			port := binary.BigEndian.Uint16(h[1:3])
			ip := net.IP(h[3:7])
			dest := ip.String()
			if h[3] == 0 && h[4] == 0 && h[5] == 0 && h[6] != 0 {
				name, _ := r.ReadString(0)
				dest = "name:" + strings.TrimSuffix(name, "\x00")
			}
			got <- "4 " + strings.TrimSuffix(user, "\x00") + " " + dest + ":" + itoa(port)
			c.Write([]byte{0, reply4, 0, 0, 0, 0, 0, 0})
		case 5:
			n, _ := r.ReadByte()
			methods := make([]byte, n)
			io.ReadFull(r, methods)
			auth := ""
			if bytes.IndexByte(methods, 2) >= 0 {
				c.Write([]byte{5, 2})
				r.ReadByte()
				ul, _ := r.ReadByte()
				u := make([]byte, ul)
				io.ReadFull(r, u)
				pl, _ := r.ReadByte()
				pw := make([]byte, pl)
				io.ReadFull(r, pw)
				auth = string(u) + ":" + string(pw)
				c.Write([]byte{1, 0})
			} else {
				c.Write([]byte{5, 0})
			}
			var h [4]byte
			io.ReadFull(r, h[:])
			var dest string
			switch h[3] {
			case 1:
				b := make([]byte, 4)
				io.ReadFull(r, b)
				dest = net.IP(b).String()
			case 3:
				l, _ := r.ReadByte()
				b := make([]byte, l)
				io.ReadFull(r, b)
				dest = "name:" + string(b)
			}
			var pb [2]byte
			io.ReadFull(r, pb[:])
			got <- "5 " + auth + " " + dest + ":" + itoa(binary.BigEndian.Uint16(pb[:]))
			c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		default:
			return
		}
		io.Copy(c, r)
	}()
	return ln.Addr().String(), got
}

func itoa(n uint16) string { return strconv.Itoa(int(n)) }

func TestProxyDial(t *testing.T) {
	cases := []struct {
		url, target, want string
	}{
		{"socks4://scan@%s", "127.0.0.1:445", "4 scan 127.0.0.1:445"},
		{"socks4://%s", "localhost:445", "4  127.0.0.1:445"},
		{"socks4a://%s", "dc01.corp.local:445", "4  name:dc01.corp.local:445"},
		{"socks5://%s", "localhost:445", "5  127.0.0.1:445"},
		{"socks5h://u:p%40ss@%s", "dc01.corp.local:445", "5 u:p@ss name:dc01.corp.local:445"},
	}
	for _, c := range cases {
		addr, got := fakeSOCKS(t, 0x5A)
		p, err := ParseProxy(strings.Replace(c.url, "%s", addr, 1))
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := p.DialContext(ctx, "tcp", c.target)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if g := <-got; g != c.want {
			t.Errorf("%s: proxy saw %q, want %q", c.url, g, c.want)
		}
		conn.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
			t.Errorf("%s: tunnel not usable: %q %v", c.url, buf, err)
		}
		conn.Close()
	}
}

func TestProxySOCKS4Rejected(t *testing.T) {
	addr, _ := fakeSOCKS(t, 0x5B)
	p, _ := ParseProxy("socks4://" + addr)
	if _, err := p.DialContext(context.Background(), "tcp", "127.0.0.1:445"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("want rejection, got %v", err)
	}
}

func TestProxyTimeout(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	for _, s := range []string{"socks4", "socks5"} {
		p, _ := ParseProxy(s + "://" + ln.Addr().String())
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		start := time.Now()
		_, err := p.DialContext(ctx, "tcp", "127.0.0.1:445")
		cancel()
		if err == nil || time.Since(start) > time.Second {
			t.Fatalf("%s: err=%v after %v", s, err, time.Since(start))
		}
	}
}

func TestParseProxy(t *testing.T) {
	p, err := ParseProxy("socks5://alice:hunter2@10.0.0.1")
	if err != nil || p.Addr != "10.0.0.1:1080" || p.User != "alice" || p.Pass != "hunter2" {
		t.Fatalf("%+v %v", p, err)
	}
	if s := p.String(); strings.Contains(s, "hunter2") || strings.Contains(s, "alice") {
		t.Fatalf("String leaks credentials: %s", s)
	}
	for _, bad := range []string{"http://h:8080", "h:1080", "socks5://", "socks4://u:p@h", "socks5://h:0", "socks5://h:1080/x"} {
		if _, err := ParseProxy(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := ParseProxy("socks5://alice:hunter2@h:bad"); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error must not echo the URL: %v", err)
	}
}
