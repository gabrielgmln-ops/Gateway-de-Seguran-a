// Caminho: internal/clientip/clientip_test.go
package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name    string
		trusted string
		remote  string
		xff     []string
		want    string
	}{
		{"sem proxy confiável ignora XFF forjado", "", "203.0.113.9:5000", []string{"1.2.3.4"}, "203.0.113.9"},
		{"proxy confiável: último salto não confiável", "10.0.0.0/8", "10.0.0.2:80", []string{"198.51.100.7"}, "198.51.100.7"},
		{"cliente forja a esquerda; vale o da direita", "10.0.0.0/8", "10.0.0.2:80", []string{"1.1.1.1, 198.51.100.7"}, "198.51.100.7"},
		{"cadeia de proxies confiáveis", "10.0.0.0/8", "10.0.0.2:80", []string{"198.51.100.7, 10.0.0.5"}, "198.51.100.7"},
		{"várias linhas de cabeçalho", "10.0.0.0/8", "10.0.0.2:80", []string{"198.51.100.7", "10.0.0.5"}, "198.51.100.7"},
		{"valor malformado: usa o proxy", "10.0.0.0/8", "10.0.0.2:80", []string{"lixo"}, "10.0.0.2"},
		{"tudo confiável: o mais à esquerda", "10.0.0.0/8", "10.0.0.2:80", []string{"10.0.0.9"}, "10.0.0.9"},
		{"proxy confiável sem XFF", "10.0.0.0/8", "10.0.0.2:80", nil, "10.0.0.2"},
		{"ipv4 mapeado em ipv6 é normalizado", "", "[::ffff:203.0.113.9]:1", nil, "203.0.113.9"},
		{"ipv6", "", "[2001:db8::1]:443", nil, "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := New(tc.trusted)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := res.ClientIP(r); got != tc.want {
				t.Errorf("ClientIP = %q, esperado %q", got, tc.want)
			}
		})
	}
}

func TestNewRejectsInvalidCIDR(t *testing.T) {
	if _, err := New("10.0.0.0/8, nao-e-cidr"); err == nil {
		t.Fatal("CIDR inválido foi aceito")
	}
}

func TestUnparsableRemoteAddr(t *testing.T) {
	res, _ := New("")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "@"
	if got := res.ClientIP(r); got != "@" {
		t.Errorf("ClientIP = %q", got)
	}
}
