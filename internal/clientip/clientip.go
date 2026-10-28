// Caminho: internal/clientip/clientip.go
//
// Pacote clientip: descobre o IP REAL do cliente de forma segura.
//
// O problema: se o gateway confiasse cegamente no cabeçalho X-Forwarded-For,
// um atacante enviaria "X-Forwarded-For: 1.2.3.4" a cada requisição e trocaria
// de "IP" à vontade, escapando do bloqueio e do rate limit.
//
// A solução: o cabeçalho só é considerado quando a conexão TCP vem de um proxy
// CONFIÁVEL (ex.: o load balancer), definido em TRUSTED_PROXIES. Mesmo assim,
// lemos o cabeçalho da DIREITA para a esquerda e paramos no primeiro IP não
// confiável: os itens à esquerda podem ter sido inventados pelo cliente.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver guarda as redes de proxies confiáveis.
type Resolver struct {
	trusted []netip.Prefix // netip.Prefix representa uma rede CIDR, ex.: 10.0.0.0/8
}

// New cria o resolvedor a partir de uma lista de CIDRs separados por vírgula.
// Lista vazia = nenhum proxy confiável (usa sempre o IP da conexão TCP).
func New(cidrs string) (*Resolver, error) {
	r := &Resolver{}
	for _, raw := range strings.Split(cidrs, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES contém CIDR inválido %q: %w", raw, err)
		}
		r.trusted = append(r.trusted, p.Masked())
	}
	return r, nil
}

// isTrusted diz se o endereço pertence a algum proxy confiável.
func (r *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP devolve o IP do cliente como texto normalizado.
// A assinatura é compatível com server.ClientIP(resolve func(*http.Request) string).
func (r *Resolver) ClientIP(req *http.Request) string {
	remote, ok := parseRemote(req.RemoteAddr)
	if !ok {
		return req.RemoteAddr
	}
	// A conexão não veio de um proxy confiável: o cabeçalho é ignorado por completo.
	if !r.isTrusted(remote) {
		return remote.String()
	}

	// Junta todas as ocorrências do cabeçalho, já que pode haver mais de uma linha.
	var hops []string
	for _, v := range req.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...) // "..." expande o slice, como *lista no Python
	}

	// Da direita para a esquerda: o primeiro IP não confiável é o cliente.
	// "for i := len(hops) - 1; i >= 0; i--" equivale a "for h in reversed(hops)".
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// Valor malformado: não há como confiar no que está à esquerda.
			// Fica com o último salto confiável conhecido (o próprio proxy).
			return remote.String()
		}
		a = a.Unmap() // "::ffff:1.2.3.4" vira "1.2.3.4", para que o mesmo IP gere uma só chave
		if !r.isTrusted(a) {
			return a.String()
		}
		remote = a
	}
	// Todos os saltos são confiáveis: o mais à esquerda é o cliente.
	return remote.String()
}

func parseRemote(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}
