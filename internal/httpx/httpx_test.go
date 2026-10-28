// Caminho: internal/httpx/httpx_test.go
package httpx

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	if RequestIDFrom(ctx) != "" || ClientIPFrom(ctx) != "" || ClientIDFrom(ctx) != "" {
		t.Fatal("contexto vazio deveria devolver strings vazias")
	}
	ctx = WithClientID(WithClientIP(WithRequestID(ctx, "r1"), "1.2.3.4"), "app")
	if RequestIDFrom(ctx) != "r1" || ClientIPFrom(ctx) != "1.2.3.4" || ClientIDFrom(ctx) != "app" {
		t.Fatal("valores do contexto incorretos")
	}
}

func TestWriteError(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(WithRequestID(r.Context(), "abc"))
	rec := httptest.NewRecorder()
	WriteError(rec, r, 418, "codigo", "mensagem")

	var body ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 418 || body.Error != "codigo" || body.Message != "mensagem" || body.RequestID != "abc" {
		t.Errorf("resposta inesperada: %d %+v", rec.Code, body)
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Error("Content-Type incorreto")
	}
}
