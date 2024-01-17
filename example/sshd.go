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
	"log"
	"os"
	"time"

	. "github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
)

const (
	Addr      = ":2222"
)

var (
	letf = log.New(os.Stdout, BUG, log.Ltime|log.Lshortfile)
	ltf  = log.New(os.Stdout, " ", log.Ltime|log.Lshortfile)

	//go:embed authorized_keys
	authorized_keys []byte
)

func main() {
	defer closer.Close()
	closer.Bind(func() {
		AllDone(os.Getpid())
	})

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	sshd := gl.Server{
		Addr: Addr,
		// next for ssh -R host:port:x:x
		ReversePortForwardingCallback: gl.ReversePortForwardingCallback(func(ctx gl.Context, host string, port uint32) bool {
			ltf.Println("attempt to bind", host, port, "granted")
			return true
		}),
		RequestHandlers: map[string]gl.RequestHandler{
			"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
			"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
		},
		// before for ssh ssh -R host:port:x:x

		// next for ssh -L x:dhost:dport
		LocalPortForwardingCallback: gl.LocalPortForwardingCallback(func(ctx gl.Context, dhost string, dport uint32) bool {
			ltf.Println("accepted forward", dhost, dport)
			return true
		}),
		ChannelHandlers: map[string]gl.ChannelHandler{
			"session":      SessionHandler,        // to allow agent forwarding
			"direct-tcpip": gl.DirectTCPIPHandler, // to allow local forwarding
		},
		// before for ssh -L x:dhost:dport

		SubsystemHandlers: map[string]gl.SubsystemHandler{
			"sftp":           SubsystemHandlerSftp,  // to allow sftp
			AgentRequestType: SubsystemHandlerAgent, // to allow agent forwarding
		},
		SessionRequestCallback: SessionRequest,     //SessionRequestCallback,
		IdleTimeout:            -time.Second * 100, //-ClientAliveInterval
		MaxTimeout:             -time.Second * 300, //-ServerAliveCountMax*ClientAliveInterval
	}

	cwd, err := os.Getwd()
	if err != nil {
		letf.Fatal(err)
		return
	}

	// next for server key
	pri := GetHostKey(cwd) // /etc/ssh
	pemBytes, err := os.ReadFile(pri)
	var key gl.Signer
	if err != nil {
		key, err = GenerateSigner(pri)
	} else {
		key, err = ssh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		letf.Fatal(err)
		return
	}

	sshd.AddHostKey(key)
	if len(sshd.HostSigners) < 1 {
		ltf.Fatal("host key was not properly added")
		return
	}
	// before for server key

	// next for client keys
	authorized := GetUserKeys(cwd)                              //.ssh
	authorized = BytesToAuthorized(authorized_keys, authorized) //from embed

	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		ltf.Println("user", ctx.User(), "from", ctx.RemoteAddr())
		// ltf.Println("used public key", string(ssh.MarshalAuthorizedKey(key)))
		ltf.Println("used public key", ssh.FingerprintSHA256(key))

		authorized = KeyToAuthorized(key, authorized) //from first user
		return Authorized(key, authorized)
	})

	sshd.SetOption(publicKeyOption)
	// before for client keys

	//only for shell or exec
	gl.Handle(func(s gl.Session) {
		ShellOrExec(s)
	})

	ltf.Println("starting ssh server on", sshd.Addr)
	letf.Fatal(sshd.ListenAndServe())

}

func SessionRequest(s gl.Session, requestType string) bool {
	if s == nil {
		return false
	}
	ltf.Println(s.RemoteAddr(), requestType, s.Command())
	return true
}
