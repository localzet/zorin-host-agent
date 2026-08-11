package main

import (
	"bufio"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestPrivateIPv4(t *testing.T) {
	tests := map[string]bool{
		"10.1.2.3":       true,
		"172.16.0.1":     true,
		"172.31.255.254": true,
		"172.32.0.1":     false,
		"192.168.50.2":   true,
		"169.254.1.9":    true,
		"127.0.0.1":      false,
		"8.8.8.8":        false,
	}

	for input, want := range tests {
		if got := isPrivateIPv4(net.ParseIP(input)); got != want {
			t.Fatalf("isPrivateIPv4(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestPortableDeepLink(t *testing.T) {
	expires := time.Unix(1_800_000_000, 0)
	deepLink := portableDeepLink(
		"192.168.1.25",
		47472,
		expires,
		"00112233445566778899aabbccddeeff",
	)

	parsed, err := url.Parse(deepLink)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "zorintrust" || parsed.Host != "connect" {
		t.Fatalf("unexpected deep link target: %s", deepLink)
	}

	query := parsed.Query()
	if query.Get("host") != "192.168.1.25" {
		t.Fatalf("unexpected host: %q", query.Get("host"))
	}
	if query.Get("port") != "47472" {
		t.Fatalf("unexpected port: %q", query.Get("port"))
	}
	if query.Get("expires") != "1800000000" {
		t.Fatalf("unexpected expires: %q", query.Get("expires"))
	}
	if query.Get("mode") != "portable" {
		t.Fatalf("unexpected mode: %q", query.Get("mode"))
	}
}

func TestConnectionTransport(t *testing.T) {
	loopback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12000}
	direct := &net.TCPAddr{IP: net.ParseIP("192.168.1.20"), Port: 12000}

	if got := connectionTransport(loopback); got != "USB / ADB" {
		t.Fatalf("loopback transport = %q", got)
	}
	if got := connectionTransport(direct); got != "Direct LAN" {
		t.Fatalf("direct transport = %q", got)
	}
}

func TestPortableHandshakeRejectsMissingInvitation(t *testing.T) {
	identity, err := newEphemeralIdentity()
	if err != nil {
		t.Fatal(err)
	}

	agent := &Agent{
		identity:        identity,
		hostPub:         identity.PublicDER(),
		hostFP:          identity.Fingerprint(),
		cfg:             Config{PairedPhones: map[string]string{}},
		portable:        true,
		portableInvite:  "00112233445566778899aabbccddeeff",
		portableExpires: time.Now().Add(time.Minute),
		sessions:        map[string]Session{},
		live:            map[string]*liveSession{},
	}

	hostSide, phoneSide := net.Pipe()
	defer phoneSide.Close()
	go agent.handle(hostSide)

	reader := bufio.NewReader(phoneSide)
	if _, err := readFrame(reader); err != nil {
		t.Fatal(err)
	}

	if err := writeLines(phoneSide, "PHONE_PUB fake", "END"); err != nil {
		t.Fatal(err)
	}

	frame, err := readFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if frame["AUTH"] != "FAIL portable-invite" {
		t.Fatalf("AUTH=%q", frame["AUTH"])
	}
}
