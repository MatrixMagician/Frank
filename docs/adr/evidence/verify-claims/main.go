package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

func check(name string, got, want any) {
	status := "FAIL"
	if fmt.Sprint(got) == fmt.Sprint(want) {
		status = "ok"
	}
	fmt.Printf("%-4s %-52s got=%v want=%v\n", status, name, got, want)
}

func netipClaims() {
	p4 := netip.MustParsePrefix("192.0.2.0/24")
	p6 := netip.MustParsePrefix("2001:db8::/32")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	plain := netip.MustParseAddr("192.0.2.1")
	zoned := netip.MustParseAddr("fe80::1%eth0")

	check("ip4 prefix contains plain v4", p4.Contains(plain), true)
	check("ip4 prefix contains v4-mapped v6", p4.Contains(mapped), false)
	check("ip4 prefix contains mapped.Unmap()", p4.Contains(mapped.Unmap()), true)
	check("ip6 prefix contains zoned addr", p6.Contains(zoned), false)
	check("one ParsePrefix handles both families", p6.Contains(netip.MustParseAddr("2001:db8::1")), true)
}

type cfg struct {
	Rate      *int  `json:"rate"`
	TLSVerify *bool `json:"tls_verify"`
}

func jsonClaims() {
	var c cfg
	d := json.NewDecoder(strings.NewReader(`{"rate":0,"typo_key":1}`))
	d.DisallowUnknownFields()
	err := d.Decode(&c)
	check("DisallowUnknownFields rejects typo", err != nil, true)

	c = cfg{}
	_ = json.Unmarshal([]byte(`{"rate":0}`), &c)
	check("pointer distinguishes set-zero from absent", c.Rate != nil && *c.Rate == 0 && c.TLSVerify == nil, true)
}

func tlsClaims() {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "frank.test"},
		DNSNames:     []string{"frank.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		fmt.Println("FAIL cert:", err)
		return
	}
	srvCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert}})
	if err != nil {
		fmt.Println("FAIL listen:", err)
		return
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); time.Sleep(50 * time.Millisecond); c.Close() }()
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		fmt.Println("FAIL dial:", err)
		return
	}
	hookCalled := false
	var hookChains int
	conn := tls.Client(raw, &tls.Config{
		ServerName:             "frank.test",
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verified [][]*x509.Certificate) error {
			hookCalled = true
			hookChains = len(verified)
			return nil
		},
	})
	if err := conn.Handshake(); err != nil {
		fmt.Println("FAIL handshake:", err)
		return
	}
	st := conn.ConnectionState()
	check("InsecureSkipVerify still populates PeerCertificates", len(st.PeerCertificates), 1)
	check("VerifiedChains nil under InsecureSkipVerify", len(st.VerifiedChains), 0)
	check("VerifyPeerCertificate invoked anyway", hookCalled, true)
	check("hook receives no verified chains", hookChains, 0)
	check("VersionName renders", tls.VersionName(st.Version), "TLS 1.3")
	check("CipherSuiteName renders", strings.HasPrefix(tls.CipherSuiteName(st.CipherSuite), "TLS_"), true)

	pool := x509.NewCertPool()
	leaf := st.PeerCertificates[0]
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: "frank.test", Roots: pool})
	check("self-verify against empty pool fails as expected", verr != nil, true)
	pool.AddCert(leaf)
	_, verr = leaf.Verify(x509.VerifyOptions{DNSName: "frank.test", Roots: pool})
	check("self-verify against seeded pool succeeds", verr == nil, true)
	conn.Close()
}

func main() {
	fmt.Println("== netip / SPF mechanism matching ==")
	netipClaims()
	fmt.Println("\n== encoding/json config decoding ==")
	jsonClaims()
	fmt.Println("\n== crypto/tls capture-without-trust ==")
	tlsClaims()
}
