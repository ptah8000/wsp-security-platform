//go:build windows

package rbi

func defaultDockerHostOS() string {
	return "npipe:////./pipe/docker_engine"
}
