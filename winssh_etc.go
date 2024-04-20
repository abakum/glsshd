//go:build !windows
// +build !windows

package winssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"syscall"

	gl "github.com/gliderlabs/ssh"
)

// get authorized keys paths
func GetUserKeysPaths(ssh string, fns ...string) []string {
	return append(fns[:],
		path.Join(ssh, authorizedKeys),
		path.Join("~", ".ssh", authorizedKeys),
		path.Join("/etc", "dropbear", authorizedKeys),
	)
}

// get one key
func GetHostKey(ssh string) (pri string) {
	for _, dir := range []string{
		path.Join("/etc", "ssh"),
		path.Join("/etc", "dropbear"),
		ssh,
	} {
		for _, key := range []string{
			"ssh_host_ecdsa_key",
			"ssh_host_ed25519_key",
			sshHostKey,
		} {
			pri = path.Join(dir, key)
			ltf.Println(pri)
			_, err := os.Stat(pri)
			if err == nil {
				return
			}
		}
	}
	return
}

// unix sock
func pipe(_ *session) string {
	const (
		agentTempDir    = "auth-agent"
		agentListenFile = "listener.sock"
	)
	dir, err := os.MkdirTemp("", agentTempDir)
	if err != nil {
		dir = os.TempDir()
	}
	return path.Join(dir, agentListenFile)
}

// close sock then rm parent dir
func doner(l net.Listener, s gl.Session) {
	<-s.Context().Done()
	p := l.Addr().String()
	ltf.Println(p, "done")
	l.Close()
	dir := path.Dir(p)
	if dir == os.TempDir() {
		// only rm dir case its parent is /tmp
		os.Remove(dir)
	}
}

// SubsystemHandlers for agent
func SubsystemHandlerAgent(s gl.Session) {
	l, err := NewAgentListener(s)
	if err != nil {
		return
	}
	defer l.Close()
	go doner(l, s)
	gl.ForwardAgentConnections(l, s)
}

// NewAgentListener sets up a temporary Unix socket that can be communicated
// to the session environment and used for forwarding connections.
func NewAgentListener(s gl.Session) (net.Listener, error) {
	p := getPipe(s)
	if p == "" {
		return nil, fmt.Errorf("not found %s", SSH_AUTH_SOCK)
	}
	l, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func AllDone(ppid int) (err error) {
	ltf.Println("AllDone", ppid)
	KidsDone(ppid)
	return PDone(ppid)
}

func KidsDone(ppid int) (err error) {
	ltf.Println("KidsDone", ppid)
	pgid, err := syscall.Getpgid(ppid)
	if err == nil {
		err = syscall.Kill(-pgid, 15)
		if err == nil {
			ltf.Println("pgid", pgid, "done")
			return
		}
	}
	return
}

func Env(s gl.Session, shell string) (e []string) {
	e = s.Environ()
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
	return
}

// `ssh -p 2222 a@127.0.0.1 command`
// `ssh -p 2222 a@127.0.0.1 -T`
func NoPTY(s gl.Session) {
	args, cmdLine := ShArgs(s)
	e := Env(s, args[0])

	cmd := exec.Command(args[0], args[1:]...)
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
