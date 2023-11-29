package winssh

import (
	"strings"

	"github.com/gliderlabs/ssh"
)

const (
	SSH_AUTH_SOCK = "SSH_AUTH_SOCK"
)

func getPipe(s ssh.Session) string {
	const (
		SSH_AUTH_SOCK_ = SSH_AUTH_SOCK + "="
	)
	for _, e := range s.Environ() {
		if strings.HasPrefix(e, SSH_AUTH_SOCK_) {
			return strings.TrimPrefix(e, SSH_AUTH_SOCK_)
		}
	}
	return ""
}
