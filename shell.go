package winssh

import (
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/abakum/go-console"
	gl "github.com/gliderlabs/ssh"
)

// `ssh -p 2222 a@127.0.0.1 command`
// `ssh -p 2222 a@127.0.0.1 -T`
func NoPTY(s gl.Session) {
	args := ShArgs(s.Command())
	e := Env(s, args[0])

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = Home(s)
	cmd.Env = append(os.Environ(), e...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println("unable to open stdout pipe", err)
		return
	}

	cmd.Stderr = cmd.Stdout

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Println("unable to open stdin pipe", err)
		return
	}

	err = cmd.Start()
	if err != nil {
		log.Println("could not start", args, err)
		return
	}
	ppid := cmd.Process.Pid
	log.Println(args, ppid)

	go func() {
		<-s.Context().Done()
		stdout.Close()
	}()

	go io.Copy(stdin, s)
	io.Copy(s, stdout)
	log.Println(args, "done")
}

// for shell and exec
func ShellOrExec(s gl.Session) {
	RemoteAddr := s.RemoteAddr()
	defer func() {
		log.Println(RemoteAddr, "done")
		if s != nil {
			s.Close()
		}
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
		log.Println("unable to create console", err)
		NoPTY(s)
		return
	}
	args := ShArgs(s.Command())
	defer func() {
		log.Println(args, "done")
		if stdout != nil {
			stdout.Close()
		}
	}()
	stdout.SetCWD(Home(s))
	stdout.SetENV(Env(s, args[0]))
	err = stdout.Start(args)
	if err != nil {
		log.Println("unable to start", args, err)
		NoPTY(s)
		return
	}

	ppid, _ := stdout.Pid()
	log.Println(args, ppid)
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
				log.Println("PTY SetSize", win)
				if win.Height == 0 && win.Width == 0 {
					stdout.Close()
					return
				}
				if err := stdout.SetSize(win.Width, win.Height); err != nil {
					log.Println(err)
				}
			}
		}
	}()

	go io.Copy(stdout, s)
	io.Copy(s, stdout)
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
