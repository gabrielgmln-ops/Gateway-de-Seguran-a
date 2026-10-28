# Caminho: Dockerfile
#
# Build em dois estágios (multi-stage):
#  1. "build": imagem com o compilador Go, que gera binários estáticos.
#  2. "runtime": imagem distroless, sem shell nem gerenciador de pacotes, com usuário
#     não-root. Isso reduz a superfície de ataque (OWASP API8).
#
# Comparação com Python: em Python a imagem final precisaria do interpretador e
# das dependências instaladas. Em Go, o binário compilado já é autossuficiente.

FROM golang:1.24-alpine AS build
WORKDIR /src

# Copia primeiro só os arquivos de dependências para aproveitar o cache de camadas
# (o mesmo truque de copiar o requirements.txt antes do código no Python).
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 gera binários 100% estáticos; -trimpath remove caminhos locais do binário;
# -ldflags="-s -w" remove símbolos de debug (binário menor).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mockservice ./cmd/mockservice

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/gateway /usr/local/bin/gateway
COPY --from=build /out/mockservice /usr/local/bin/mockservice
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
