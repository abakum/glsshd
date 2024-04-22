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
	"sync"
	"syscall"
	"unsafe"

	"github.com/Microsoft/go-winio"
	gl "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

const (
	PIPE          = `\\.\pipe`
	authAgentPipe = "auth-agent"
)

// get authorized keys paths
func GetUserKeysPaths(ssh string, fns ...string) []string {
	return append(fns[:],
		filepath.Join(ssh, authorizedKeys),
		filepath.Join(os.Getenv("USERPROFILE"), ".ssh", authorizedKeys),
		filepath.Join(os.Getenv("ALLUSERSPROFILE"), "ssh", administratorsAuthorizedKeys),
	)
}

// get one key
func GetHostKey(ssh string) (pri string) {
	for _, dir := range []string{
		filepath.Join(os.Getenv("ALLUSERSPROFILE"), "ssh"),
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

// powershell instead cmd
func psArgs(s gl.Session) (args []string) {
	args = []string{"powershell.exe", "-NoProfile", "-NoLogo"}
	if s.RawCommand() != "" {
		args = append(args,
			"-NonInteractive",
			"-Command",
		)
		args = append(args, s.RawCommand())
	} else {
		args = append(args,
			"-Mta", //for Win7
		)
	}
	return
}

// https://gist.github.com/gekigek99/94f3629e929d514ca6eed55e111ae442
// GetTreePids will return a list of pids that represent the tree of process pids originating from the specified one.
// (they are ordered: [parent, 1 gen child, 2 gen child, ...])
func GetTreePids(rootPid uint32) ([]uint32, error) {
	// https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
	procEntry := syscall.ProcessEntry32{}
	parentLayer := []uint32{rootPid}
	treePids := parentLayer
	foundRootPid := false

	snapshot, err := syscall.CreateToolhelp32Snapshot(uint32(syscall.TH32CS_SNAPPROCESS), 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)

	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	for {
		// set procEntry to the first process in the snapshot
		err = syscall.Process32First(snapshot, &procEntry)
		if err != nil {
			return nil, err
		}

		// loop through the processes in the snapshot, if the parent pid of the analyzed process
		// is in in the parent layer, append the analyzed process pid in the child layer
		var childLayer []uint32
		for {
			if procEntry.ProcessID == rootPid {
				foundRootPid = true
			}

			if contains(parentLayer, procEntry.ParentProcessID) {
				// avoid adding a pid if it's already contained in treePids
				// useful for pid 0 whose ppid is 0 and would lead to recursion (windows)
				if !contains(treePids, procEntry.ProcessID) {
					childLayer = append(childLayer, procEntry.ProcessID)
				}
			}

			// advance to next process in snapshot
			err = syscall.Process32Next(snapshot, &procEntry)
			if err != nil {
				// if there aren't anymore processes to be analyzed, break out of the loop
				break
			}
		}

		// if the specified rootPid is not found, return error
		if !foundRootPid {
			return nil, fmt.Errorf("specified rootPid not found")
		}

		// fmt.Println(childLayer)

		// there are no more child processes, return the process tree
		if len(childLayer) == 0 {
			return treePids, nil
		}

		// append the child layer to the tree pids
		treePids = append(treePids, childLayer...)

		// to analyze the next layer, set the child layer to be the new parent layer
		parentLayer = childLayer
	}
}

// contain e in list
func contains(list []uint32, e uint32) bool {
	for _, l := range list {
		if l == e {
			return true
		}
	}
	return false
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
		// fmt.Sprintf("PROMPT=%s@%s$S$P$G", s.User(), os.Getenv("COMPUTERNAME")),
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
