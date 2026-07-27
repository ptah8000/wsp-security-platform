//go:build !windows

package rbi

import (
	"context"
	"fmt"
	"net"
)

func dialDockerNpipe(ctx context.Context, path string) (net.Conn, error) {
	return nil, fmt.Errorf("docker named pipes are only supported on Windows (path=%s)", path)
}
