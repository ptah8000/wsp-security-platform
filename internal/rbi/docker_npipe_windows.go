//go:build windows

package rbi

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

func dialDockerNpipe(ctx context.Context, path string) (net.Conn, error) {
	// Normalize npipe path forms to \\.\pipe\docker_engine style.
	p := strings.ReplaceAll(path, "/", `\`)
	if !strings.HasPrefix(p, `\\.\pipe\`) {
		p = strings.TrimPrefix(p, `\`)
		switch {
		case strings.HasPrefix(p, `.\pipe\`):
			p = `\\` + p
		case strings.HasPrefix(p, `pipe\`):
			p = `\\.\` + p
		default:
			p = `\\.\pipe\docker_engine`
		}
	}

	timeout := 10 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			timeout = d
		}
	}
	// Prefer context-aware dial when available via deadline wrapper.
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := winio.DialPipe(p, &timeout)
		ch <- result{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.c, r.err
	}
}
