package winssh

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/abakum/go-ansiterm"
	"github.com/abakum/go-console"
	gl "github.com/gliderlabs/ssh"
	"github.com/mitchellh/go-ps"
)

// set Home of user
func Home(s gl.Session) string {
	u, err := user.Lookup(s.User())
	if err != nil {
		return "/nonexistent"
	}
	return u.HomeDir
}

// shell
func ShArgs(s gl.Session) (args []string, cmdLine string) {
	sh := "bash"
	env := "SHELL"
	win := runtime.GOOS == "windows"
	if win {
		sh = "cmd.exe"
		env = "COMSPEC"
	}
	var err error
	for _, shell := range []string{
		os.Getenv(env),
		sh,
	} {
		if cmdLine, err = exec.LookPath(shell); err == nil {
			break
		}
	}
	if err != nil {
		cmdLine = sh
	}
	args = []string{cmdLine}
	if s.RawCommand() != "" {
		if win {
			cmdLine = fmt.Sprintf(`%s /c %s`, quote(args[0]), quote(s.RawCommand()))
			args = append(args, "/c")
		} else {
			cmdLine = fmt.Sprintf(`%s -c %s`, args[0], s.RawCommand())
			args = append(args, "-c")
		}
		args = append(args, s.RawCommand())
	}
	return
}

func quote(s string) string {
	if strings.Contains(s, " ") {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

// for shell and exec
func ShellOrExec(s gl.Session) {
	RemoteAddr := s.RemoteAddr()
	defer func() {
		ltf.Println(RemoteAddr, "done")
	}()

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		NoPTY(s)
		return
	}
	// ssh -p 2222 a@127.0.0.1
	// ssh -p 2222 a@127.0.0.1 -t commands
	stdout, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)
	if err != nil {
		letf.Println("unable to create console", err)
		NoPTY(s)
		return
	}
	args, cmdLine := ShArgs(s)
	stdout.SetCWD(Home(s))
	stdout.SetENV(Env(s, args[0]))
	err = stdout.Start(args)
	if err != nil {
		letf.Println("unable to start", cmdLine, err)
		NoPTY(s)
		return
	}

	SetConsoleTitle(s)
	ppid, _ := stdout.Pid()
	ltf.Println(cmdLine, ppid)
	go func() {
		for {
			if stdout == nil || s == nil {
				return
			}
			select {
			case <-s.Context().Done():
				stdout.Close()
				return
			case win := <-winCh:
				ltf.Println("PTY SetSize", win)
				if win.Height == 0 && win.Width == 0 {
					stdout.Close()
					return
				}
				if err := stdout.SetSize(win.Width, win.Height); err != nil {
					letf.Println(err)
				}
			}
		}
	}()

	go io.Copy(stdout, s)
	go io.Copy(s, stdout)
	ps, err := stdout.Wait()
	ec := 0
	if err == nil && ps != nil {
		ec = ps.ExitCode()
	}
	ltf.Println(cmdLine, "done", err, ec)
}

func PidDone(pid int) {
	Process, err := os.FindProcess(pid)
	if err == nil {
		ltf.Println("pid", pid, "done", Process.Kill())
		return
	}
	ltf.Println("pid", pid, err)
}

func KidsDone(ppid int) {
	if ppid < 1 {
		return
	}
	pes, err := ps.Processes()
	if err != nil {
		return
	}
	for _, p := range pes {
		if p == nil {
			continue
		}
		if p.PPid() == ppid && p.Pid() != ppid {
			PidDone(p.Pid())
		}
	}
}

// Баннер без префикса SSH2
func CutSSH2(s string) string {
	const SSH2 = "SSH-2.0-"
	after, _ := strings.CutPrefix(s, SSH2)
	return after
}

// Меняю заголовок окна у клиента
func SetConsoleTitle(s gl.Session) {
	const OSSH = "OpenSSH_for_Windows"
	clientVersion := s.Context().ClientVersion()
	if s.RawCommand() == "" && !strings.Contains(clientVersion, OSSH) {
		// Not for OpenSSH_for_Windows
		time.AfterFunc(time.Millisecond*333, func() {
			title := fmt.Sprintf("%c]0;%s%c", ansiterm.ANSI_ESCAPE_PRIMARY, CutSSH2(clientVersion)+"@"+CutSSH2(s.Context().ServerVersion()), ansiterm.ANSI_BEL)
			s.Write([]byte(title))
		})
	}
}
