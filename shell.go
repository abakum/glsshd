package winssh

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/abakum/go-console"
	gl "github.com/gliderlabs/ssh"
	"github.com/zzl/go-win32api/win32"
)

const shellhost = "ssh-shellhost.exe"

// for not PTY as
// `klink a@:2222 -T`
// `klink a@:2222 commands`
// `kitty_portable a@:2222 -T`
// `ssh -p 2222 a@ command`
// `ssh -p 2222 a@ -T`
func noPTY(s gl.Session) {
	shell := len(s.Command()) == 0
	args := ShArgs(s.Command())
	e := Env(s, args[0])
	args = ShellArgs(args)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = home(s)
	cmd.Env = append(os.Environ(), e...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprint(s, "unable to open stdout pipe", err)
		return
	}

	cmd.Stderr = cmd.Stdout

	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprint(s, "unable to open stdin pipe", err)
		return
	}

	err = cmd.Start()
	if err != nil {
		fmt.Fprint(s, "could not start", args, err)
		return
	}
	ppid := cmd.Process.Pid
	log.Println(args, ppid)
	if runtime.GOOS == "windows" && strings.Contains(args[0], shellhost) {
		time.Sleep(time.Millisecond * 33)
		pids, _ := GetTreePids(uint32(ppid))
		if len(pids) > 1 {
			win32.EnumWindows(syscall.NewCallback(hide), uintptr(pids[1]))
		}
	}
	go func() {
		<-s.Context().Done()
		if shell {
			fmt.Fprint(stdin, "exit\n")
			stdin.Close()
			// AllDone(ppid) //force
		}
		log.Println(args, "done")
	}()

	go io.Copy(stdin, s)
	io.Copy(s, stdout)
	err = cmd.Wait()
	if err != nil {
		log.Println(args[0], err)
	}
}

// for shell and exec
func ShellOrExec(s gl.Session) {
	shell := len(s.Command()) == 0
	RemoteAddr := s.RemoteAddr()
	defer func() {
		log.Println(RemoteAddr, "done")
		if s != nil {
			s.Close()
		}
	}()

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		noPTY(s)
		return
	}
	// for `kitty_portable a@:2222`
	// `klink a@:2222`
	// `klink a@:2222 -t commands`
	// ssh -p 2222 a@
	stdin, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)
	if err != nil {
		fmt.Fprint(s, "unable to create console", err)
		noPTY(s) // fallback
		return
	}
	stdin.SetCWD(home(s))
	args := ShArgs(s.Command())
	stdin.SetENV(Env(s, args[0]))
	defer func() {
		log.Println(args, "done")
		if stdin != nil {
			stdin.Close()
		}
	}()

	err = stdin.Start(args)
	if err != nil {
		fmt.Fprint(s, "unable to start", args, err)
		noPTY(s) // fallback
		return
	}
	log.Println(args)

	done := s.Context().Done()
	go func() {
		for {
			select {
			case <-done:
				if shell {
					fmt.Fprint(stdin, "exit\n")
					stdin.Close()
				}
				return
			case win := <-winCh:
				log.Println("PTY SetSize", win)
				if stdin == nil {
					return
				}
				if win.Height == 0 && win.Width == 0 {
					stdin.Close()
					return
				}
				if err := stdin.SetSize(win.Width, win.Height); err != nil {
					log.Println(err)
				}
			}
		}
	}()

	go io.Copy(stdin, s)
	io.Copy(s, stdin)
	if _, err := stdin.Wait(); err != nil {
		log.Println(args, err)
	}
}

// parent done
func PDone(ppid int) (err error) {
	Process, err := os.FindProcess(ppid)
	if err == nil {
		err = Process.Kill()
		if err == nil {
			log.Println("ppid", ppid, "done")
		}
	}
	return
}
