package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/volkserg/rpi5-gorouter/internal/access"
)

type fakeBackend struct {
	Tools   // методы проверок в этих тестах не вызываются
	st      Status
	applied []string
	err     error
}

func (f *fakeBackend) Status() Status                            { return f.st }
func (f *fakeBackend) Access(access.Query) (access.Result, bool) { return access.Result{}, false }
func (f *fakeBackend) Apply(user, what string) error {
	f.applied = append(f.applied, user+": "+what)
	return f.err
}

func TestSocketRoundTrip(t *testing.T) {
	// Путь к unix-сокету ограничен ~100 байтами — короткий каталог.
	dir, err := os.MkdirTemp("", "api")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")
	l, err := Listen(path)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("unix-сокеты запрещены окружением:", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: Handler(&fakeBackend{st: Status{Mode: "tproxy", Domains: 3}}, dir)}
	go srv.Serve(l)
	defer srv.Close()

	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm()&0o007 != 0 {
		t.Fatalf("права сокета: %v %v", st.Mode(), err)
	}
	c := NewClient(path)
	var got Status
	if err := c.Get(context.Background(), "/v1/status", &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "tproxy" || got.Domains != 3 {
		t.Errorf("status: %+v", got)
	}
	if err := c.Get(context.Background(), "/v1/nope", &got); err == nil {
		t.Error("неизвестный метод: ожидалась ошибка")
	}
}
