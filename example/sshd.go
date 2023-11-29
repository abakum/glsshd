/*
git clone https://github.com/abakum/winssh
go mod init github.com/abakum/winssh
go get github.com/gliderlabs/ssh
go get github.com/pkg/sftp
go get github.com/abakum/go-console
go get github.com/xlab/closer
go mod tidy
*/
package main

import (
	_ "embed" //no lint
	"fmt"
	"log"
	"os"

	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
)

const (
	Addr          = ":2222"
	SSH_AUTH_SOCK = "SSH_AUTH_SOCK="
)

var (
	//go:embed authorized_keys
	authorized_keys []byte
)

// logging sessions
func SessionRequestCallback(s gl.Session, requestType string) bool {
	if s == nil {
		return false
	}
	ptyReq, _, isPty := s.Pty()
	pr := ""
	if isPty {
		pr = fmt.Sprintf("%v", ptyReq)
	}
	log.Println(s.RemoteAddr(), requestType, s.Command(), pr)
	return true
}

func main() {
	defer closer.Close()
	closer.Bind(func() {
		winssh.AllDone(os.Getpid())
	})

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	sshd := gl.Server{
		Addr: Addr,
		// next for ssh -R host:port:x:x
		ReversePortForwardingCallback: gl.ReversePortForwardingCallback(func(ctx gl.Context, host string, port uint32) bool {
			log.Println("attempt to bind", host, port, "granted")
			return true
		}),
		RequestHandlers: map[string]gl.RequestHandler{
			"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest, // to allow remote tcp/ip forwarding
			"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest, // to allow remote tcp/ip forwarding
		},
		// before for ssh ssh -R host:port:x:x

		// next for ssh -L x:dhost:dport
		LocalPortForwardingCallback: gl.LocalPortForwardingCallback(func(ctx gl.Context, dhost string, dport uint32) bool {
			log.Println("accepted forward", dhost, dport)
			return true
		}),
		ChannelHandlers: map[string]gl.ChannelHandler{
			"session":      winssh.SessionHandler, // to allow agent forwarding
			"direct-tcpip": gl.DirectTCPIPHandler, // to allow local tcp/ip forwarding
		},
		// before for ssh -L x:dhost:dport

		SubsystemHandlers: map[string]gl.SubsystemHandler{
			"sftp":                  winssh.SubsystemHandlerSftp,  // to allow sftp
			winssh.AgentRequestType: winssh.SubsystemHandlerAgent, // to allow agent forwarding
		},
		SessionRequestCallback: SessionRequestCallback,
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
		return
	}

	// next for server key
	pri := winssh.GetHostKey(cwd) // /etc/ssh
	pemBytes, err := os.ReadFile(pri)
	var key gl.Signer
	if err != nil {
		key, err = winssh.GenerateSigner(pri)
	} else {
		key, err = ssh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		log.Fatal(err)
		return
	}

	sshd.AddHostKey(key)
	if len(sshd.HostSigners) < 1 {
		log.Fatal("host key was not properly added")
		return
	}
	// before for server key

	// next for client keys
	authorized := winssh.GetUserKeys(cwd)                              //.ssh
	authorized = winssh.BytesToAuthorized(authorized_keys, authorized) //from embed

	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		authorized = winssh.KeyToAuthorized(key, authorized) //from first user
		return winssh.Authorized(key, authorized)
	})

	sshd.SetOption(publicKeyOption)
	// before for client keys

	gl.Handle(func(s gl.Session) {
		log.Println("user", s.User())
		if s.PublicKey() != nil {
			authorizedKey := ssh.MarshalAuthorizedKey(s.PublicKey())
			log.Println("used public key", string(authorizedKey))
		}
		winssh.ShellOrExec(s)
	})

	log.Println("starting ssh server on", sshd.Addr)
	log.Fatal(sshd.ListenAndServe())

}
