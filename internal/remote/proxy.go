package remote

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// Proxy is a SOCKS proxy. socks4 and socks5 resolve the target locally;
// socks4a and socks5h pass the name to the proxy.
type Proxy struct {
	Scheme string
	Addr   string
	User   string
	Pass   string
}

func ParseProxy(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("proxy must be a URL like socks5://host:1080")
	}
	p := &Proxy{Scheme: u.Scheme}
	switch u.Scheme {
	case "socks4", "socks4a", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("proxy scheme %q not supported; use socks4, socks4a, socks5, or socks5h", u.Scheme)
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		return nil, errors.New("proxy URL must not have a path or query")
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "1080"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, errors.New("proxy port must be 1-65535")
	}
	p.Addr = net.JoinHostPort(host, port)
	if u.User != nil {
		p.User = u.User.Username()
		p.Pass, _ = u.User.Password()
		if p.Scheme[:6] == "socks4" {
			if _, set := u.User.Password(); set {
				return nil, errors.New("SOCKS4 has no password; use socks4://userid@host")
			}
		}
		if p.Scheme[:6] == "socks5" && (len(p.User) > 255 || len(p.Pass) > 255) {
			return nil, errors.New("SOCKS5 username and password are limited to 255 bytes")
		}
	}
	return p, nil
}

// String omits credentials.
func (p *Proxy) String() string { return p.Scheme + "://" + p.Addr }

func (p *Proxy) Dial(network, addr string) (net.Conn, error) {
	return p.DialContext(context.Background(), network, addr)
}

func (p *Proxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if p.Scheme == "socks4" || p.Scheme == "socks5" {
		ip, err := resolve(ctx, host, p.Scheme == "socks4")
		if err != nil {
			return nil, err
		}
		host = ip.String()
	}
	if p.Scheme[:6] == "socks5" {
		var auth *proxy.Auth
		if p.User != "" || p.Pass != "" {
			auth = &proxy.Auth{User: p.User, Password: p.Pass}
		}
		d, err := proxy.SOCKS5("tcp", p.Addr, auth, &net.Dialer{})
		if err != nil {
			return nil, err
		}
		c, err := d.(proxy.ContextDialer).DialContext(ctx, network, net.JoinHostPort(host, portStr))
		if err != nil {
			return nil, fmt.Errorf("via %s: %w", p, err)
		}
		return c, nil
	}
	return p.dialSOCKS4(ctx, host, port)
}

func resolve(ctx context.Context, host string, v4only bool) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4only && ip.To4() == nil {
			return nil, fmt.Errorf("SOCKS4 cannot reach IPv6 address %s", host)
		}
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	if v4only || len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	return ips[0], nil
}

var socks4Errors = map[byte]string{
	0x5B: "request rejected or failed",
	0x5C: "proxy could not reach identd on the client",
	0x5D: "identd user ID mismatch",
}

func (p *Proxy) dialSOCKS4(ctx context.Context, host string, port int) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return nil, fmt.Errorf("via %s: %w", p, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	req := []byte{4, 1, 0, 0}
	binary.BigEndian.PutUint16(req[2:], uint16(port))
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(req, ip...)
		req = append(req, p.User...)
		req = append(req, 0)
	} else {
		// SOCKS4a: 0.0.0.x signals that a host name follows the user ID.
		req = append(req, 0, 0, 0, 1)
		req = append(req, p.User...)
		req = append(req, 0)
		req = append(req, host...)
		req = append(req, 0)
	}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("via %s: %w", p, err)
	}
	var resp [8]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("via %s: %w", p, err)
	}
	if resp[1] != 0x5A {
		c.Close()
		msg, ok := socks4Errors[resp[1]]
		if !ok {
			msg = fmt.Sprintf("reply code 0x%02X", resp[1])
		}
		return nil, fmt.Errorf("via %s: %s", p, msg)
	}
	if !stop() {
		c.Close()
		return nil, ctx.Err()
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
