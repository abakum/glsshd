//go:build windows
// +build windows

package winssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/Microsoft/go-winio"
	gl "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

const (
	PIPE          = `\\.\pipe`
	authAgentPipe = "auth-agent"
)

// get authorized keys paths
func GetUserKeysPaths(ssh string, fns ...string) []string {
	return append(fns[:],
		filepath.Join(ssh, authorizedKeys),
		filepath.Join(UserHomeDirs(".ssh"), authorizedKeys),
		filepath.Join(EtcDirs("ssh"), administratorsAuthorizedKeys),
	)
}

// get one key
func GetHostKey(ssh string) (pri string) {
	for _, dir := range []string{
		filepath.Join(EtcDirs("ssh")),
		ssh,
	} {
		for _, key := range []string{
			"ssh_host_ecdsa_key",
			"ssh_host_ed25519_key",
			sshHostKey,
		} {
			pri = filepath.Join(dir, key)
			ltf.Println(pri)
			_, err := os.Stat(pri)
			if err == nil {
				return
			}
		}
	}
	return
}

// if s done then close l
func doner(l net.Listener, s gl.Session) {
	<-s.Context().Done()
	ltf.Println(l.Addr().String(), "done")
	l.Close()
}

// SubsystemHandlers for agent
func SubsystemHandlerAgent(s gl.Session) {
	l, err := NewAgentListener(s)
	if err != nil {
		return
	}
	defer l.Close()
	go doner(l, s)
	ForwardAgentConnections(l, s)
}

// listen pipe
func NewAgentListener(s gl.Session) (net.Listener, error) {
	p := getPipe(s)
	if p == "" {
		return nil, fmt.Errorf("not found %s", SSH_AUTH_SOCK)
	}
	l, err := winio.ListenPipe(p, nil)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// set env
func Env(s gl.Session, shell string) (e []string) {
	e = s.Environ()
	ltf.Println(e)
	ra, ok := s.RemoteAddr().(*net.TCPAddr)
	if ok {
		la, ok := s.LocalAddr().(*net.TCPAddr)
		if ok {
			e = append(e,
				fmt.Sprintf("%s=%s %d %d", "SSH_CLIENT", ra.IP, ra.Port, la.Port),
				fmt.Sprintf("%s=%s %d %s %d", "SSH_CONNECTION", ra.IP, ra.Port, la.IP, la.Port),
			)
		}
	}
	e = append(e,
		"LOGNAME="+s.User(),
	)
	ptyReq, _, isPty := s.Pty()
	if isPty {
		if ptyReq.Term != "" {
			e = append(e,
				"TERM="+ptyReq.Term,
			)
		}
		e = append(e,
			"SSH_TTY=windows-pty",
		)
	}
	e = append(e,
		fmt.Sprintf(`HOME=%s%s\%s`, os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH"), s.User()),
		fmt.Sprintf("SHELL=%s", shell),
	)
	return
}

// handle pipe connection
func ForwardAgentConnections(l net.Listener, s gl.Session) {
	sshConn := s.Context().Value(gl.ContextKeyConn).(ssh.Conn)
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			channel, reqs, err := sshConn.OpenChannel(agentChannelType, nil)
			if err != nil {
				defer conn.Close()
				return
			}
			defer channel.Close()
			go ssh.DiscardRequests(reqs)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				io.Copy(conn, channel)
				conn.Close()
				wg.Done()
			}()
			go func() {
				io.Copy(channel, conn)
				channel.CloseWrite()
				wg.Done()
			}()
			wg.Wait()
		}(conn)
	}
}

// named pipe
func pipe(sess *session) string {
	return fmt.Sprintf(`%s\%s\%s\%s`, PIPE, authAgentPipe, sess.LocalAddr(), sess.RemoteAddr())
}

// `ssh -p 2222 a@127.0.0.1 command`
// `ssh -p 2222 a@127.0.0.1 -T`
func NoPTY(s gl.Session) {
	args, cmdLine := ShArgs(s)
	e := Env(s, args[0])

	cmd := exec.Command(args[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdLine}
	cmd.Dir = Home(s)
	cmd.Env = append(os.Environ(), e...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		letf.Println("unable to open stdout pipe", err)
		return
	}

	cmd.Stderr = cmd.Stdout

	stdin, err := cmd.StdinPipe()
	if err != nil {
		letf.Println("unable to open stdin pipe", err)
		return
	}

	err = cmd.Start()
	if err != nil {
		letf.Println("could not start", cmdLine, err)
		return
	}
	ppid := cmd.Process.Pid
	ltf.Println(cmdLine, ppid)

	go func() {
		<-s.Context().Done()
		stdout.Close()
	}()

	go io.Copy(stdin, s)
	go io.Copy(s, stdout)
	ltf.Println(cmdLine, "done", cmd.Wait())
}

// ALLUSERSPROFILE
func EtcDirs(dirs ...string) (s string) {
	dirs = append([]string{os.Getenv("ALLUSERSPROFILE")}, dirs...)
	s = filepath.Join(dirs...)
	os.MkdirAll(s, 0755)
	return
}

func UserName() string {
	return os.Getenv("USERNAME")
}

func Banner(ss ...string) string {
	majorVersion, minorVersion, buildNumber := windows.RtlGetNtVersionNumbers()
	return strings.Join(append(ss,
		runtime.GOOS,
		fmt.Sprintf("%d.%d.%d", majorVersion, minorVersion, buildNumber),
	), "_")
}
