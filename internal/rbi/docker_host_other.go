//go:build !windows

package rbi

func defaultDockerHostOS() string {
	return "unix:///var/run/docker.sock"
}
