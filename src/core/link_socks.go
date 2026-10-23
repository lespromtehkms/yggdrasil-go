package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type linkSOCKS struct {
	*links
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (l *links) newLinkSOCKS() *linkSOCKS {
	lt := &linkSOCKS{
		links: l,
	}
	return lt
}

func (l *linkSOCKS) dial(_ context.Context, u *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	var proxyAuth *proxy.Auth
	if u.User != nil && u.User.Username() != "" {
		proxyAuth = &proxy.Auth{
			User: u.User.Username(),
		}
		proxyAuth.Password, _ = u.User.Password()
	}
	tlsconfig := l.tls.config.Clone()
	return l.findSuitableIP(u, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		hostport := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		dialer, err := l.tcp.dialerFor(&net.TCPAddr{
			IP:   ip,
			Port: port,
		}, info.sintf)
		if err != nil {
			return nil, err
		}
		pathtokens := strings.Split(strings.Trim(u.Path, "/"), "/")
		target := pathtokens[0]
		if target == "" {
			return nil, fmt.Errorf("target peer address missing in proxy URI path")
		}

		// Если пир указан доменом (буквами), сначала пробуем узнать его IP на самом компе,
		// чтобы прокси-серверу без DNS сразу шли готовые цифры IP:порт.
		connectTarget := target
		peerHost, peerPort, splitErr := net.SplitHostPort(target)
		if splitErr == nil && net.ParseIP(peerHost) == nil {
			if ips, lookupErr := net.LookupIP(peerHost); lookupErr == nil {
				for _, resolvedIP := range ips {
					if v4 := resolvedIP.To4(); v4 != nil {
						connectTarget = net.JoinHostPort(v4.String(), peerPort)
						break
					}
				}
				if connectTarget == target && len(ips) > 0 {
					connectTarget = net.JoinHostPort(ips[0].String(), peerPort)
				}
			}
		}

		var conn net.Conn
		scheme := strings.ToLower(u.Scheme)
		if scheme == "http" || scheme == "httptls" {
			conn, err = dialer.Dial("tcp", hostport)
			if err != nil {
				return nil, err
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			var reqBuilder strings.Builder
			fmt.Fprintf(&reqBuilder, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", connectTarget, connectTarget)
			if proxyAuth != nil {
				auth := base64.StdEncoding.EncodeToString([]byte(proxyAuth.User + ":" + proxyAuth.Password))
				fmt.Fprintf(&reqBuilder, "Proxy-Authorization: Basic %s\r\n", auth)
			}
			reqBuilder.WriteString("\r\n")
			if _, err = conn.Write([]byte(reqBuilder.String())); err != nil {
				_ = conn.Close()
				return nil, err
			}
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				_ = conn.Close()
				return nil, fmt.Errorf("HTTP proxy error: %s", resp.Status)
			}
			_ = conn.SetDeadline(time.Time{})
			if br.Buffered() > 0 {
				conn = &bufferedConn{Conn: conn, r: br}
			}
		} else {
			p, err := proxy.SOCKS5("tcp", hostport, proxyAuth, dialer)
			if err != nil {
				return nil, err
			}
			conn, err = p.Dial("tcp", connectTarget)
			if err != nil {
				return nil, err
			}
		}

		if scheme == "sockstls" || scheme == "httptls" {
			tlsconfig.ServerName = ""
			if splitErr == nil && net.ParseIP(peerHost) == nil {
				tlsconfig.ServerName = peerHost
			}
			if sni := u.Query().Get("sni"); sni != "" && net.ParseIP(sni) == nil {
				tlsconfig.ServerName = sni
			}
			tlsconfig.MinVersion = tls.VersionTLS12
			tlsconfig.MaxVersion = tls.VersionTLS13
			conn = tls.Client(conn, tlsconfig)
		}
		return conn, nil
	})
}

func (l *linkSOCKS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error) {
	return nil, fmt.Errorf("SOCKS/HTTP proxy listener not supported")
}
