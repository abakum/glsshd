package winssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/abakum/go-console"
	gl "github.com/gliderlabs/ssh"
	"github.com/zzl/go-win32api/win32"
)

const (
	shellhost = "ssh-shellhost.exe"
	M77       = time.Millisecond * 77
)

// `klink a@:2222 -T`
// `klink a@:2222 commands`
// `kitty_portable a@:2222 -T`
// `ssh -p 2222 a@ command`
// `ssh -p 2222 a@ -T`
func noPTY(s gl.Session) {
	args := ShArgs(s.Command())
	e := Env(s, args[0])

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = home(s)
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
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		noPTY(s)
		return
	}
	// `kitty_portable a@:2222`
	// `klink a@:2222`
	// `klink a@:2222 -t commands`
	// ssh -p 2222 a@
	// ssh -p 2222 a@ -t commands
	stdout, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)
	if err != nil {
		log.Println("unable to create console", err)
		if runtime.GOOS == "windows" {
			openSshPTY(s) //ugly
		} else {
			noPTY(s)
		}
		return
	}
	args := ShArgs(s.Command())
	defer func() {
		log.Println(args, "done")
		if stdout != nil {
			stdout.Close()
		}
	}()
	stdout.SetCWD(home(s))
	stdout.SetENV(Env(s, args[0]))
	err = stdout.Start(args)
	if err != nil {
		log.Println("unable to start", args, err)
		noPTY(s)
		return
	}

	log.Println(args)
	RemoteAddr := s.RemoteAddr()
	defer func() {
		log.Println(RemoteAddr, "done")
		if s != nil {
			s.Close()
		}
	}()

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
	if _, err := stdout.Wait(); err != nil {
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

func openSshPTY(s gl.Session) {
	args := ShArgs(s.Command())
	e := Env(s, args[0])
	args = ShellArgs(args)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = home(s)
	cmd.Env = append(os.Environ(), e...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println("unable to open stdout pipe", err)
		noPTY(s)
		return
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Println("unable to open stdin pipe", err)
		noPTY(s)
		return
	}

	cmdErr, tty, err := os.Pipe()
	if err != nil {
		log.Println("unable to open stderr pipe", err)
		noPTY(s)
		return
	}
	defer cmdErr.Close()
	defer tty.Close()
	cmd.Stderr = cmdErr // use cmdErr for tty

	err = cmd.Start()
	if err != nil {
		log.Println("unable to start", args, err)
		noPTY(s) // fallback
		return
	}
	defer func() {
		log.Println(args, "done")
		if stdout != nil {
			stdout.Close()
		}
	}()

	RemoteAddr := s.RemoteAddr()
	defer func() {
		log.Println(RemoteAddr, "done")
		if s != nil {
			s.Close()
		}
	}()

	ppid := cmd.Process.Pid
	log.Println(args, ppid)
	time.Sleep(M77)
	pids, _ := GetTreePids(uint32(ppid))
	var cmdHWND uintptr
	var cmdPID uint32
	if len(pids) > 1 {
		cmdPID = pids[1]
		hide := func(hwnd uintptr, lParam uintptr) uintptr {
			var dwProcessId uint32
			win32.GetWindowThreadProcessId(hwnd, &dwProcessId)
			if cmdPID == dwProcessId {
				cmdHWND = hwnd
				win32.ShowWindow(hwnd, win32.SW_HIDE)
				log.Println(hwnd, GetWindowText(hwnd), GetClassName(hwnd))
				return 0
			}
			return 1
		}
		win32.EnumWindows(syscall.NewCallback(hide), 0)
	}
	log.Println(cmdPID, cmdHWND)
	ptyReq, winCh, _ := s.Pty()
	var Width int
	SetSize := func(tty, in io.Writer, win gl.Window) error {
		if Width == win.Width {
			return nil
		}
		Width = win.Width
		log.Println("PTY SetSize", win)
		if win.Height == 0 && win.Width == 0 {
			return fmt.Errorf("0x0")
		}
		//https://github.com/PowerShell/openssh-portable/blob/4ee8dc64982b62cd520417556515383908091b76/contrib/win32/win32compat/shell-host.c#L804
		if runtime.GOARCH == "amd64" {
			//https://github.com/PowerShell/Win32-OpenSSH/issues/1222#issuecomment-409052375
			const PTY_SIGNAL_RESIZE_WINDOW uint16 = 8 //https://github.com/PowerShell/openssh-portable/blob/cb23f0d9c0f4d40edbc2863419dcff40ebd5e0a6/contrib/win32/win32compat/misc_internal.h#L32C9-L32C33
			buf := new(bytes.Buffer)
			signalPacket := []uint16{PTY_SIGNAL_RESIZE_WINDOW, uint16(win.Width), uint16(win.Height)}
			err := binary.Write(buf, binary.LittleEndian, signalPacket)
			if err != nil {
				log.Println(err)
			}
			n, err := tty.Write(buf.Bytes())
			if n != 6 || err != nil {
				log.Println(err)
			}
		} else {
			fmt.Fprintf(in, "mode")
			fmt.Fprintf(in, " con")
			fmt.Fprintf(in, " cols=%d", win.Width)
			// fmt.Fprintf(in, " lines=%d", win.Height)
		}
		fmt.Fprintf(in, "\n")
		return nil
	}

	SetSize(tty, stdin, ptyReq.Window)

	go func() {
		for {
			if stdin == nil || s == nil {
				return
			}
			select {
			case <-s.Context().Done():
				stdout.Close()
				return
			case win := <-winCh:
				err = SetSize(tty, stdin, win)
				if err != nil {
					stdout.Close()
					return
				}
			}
		}
	}()

	go io.Copy(stdin, s)
	io.Copy(s, stdout)
	err = cmd.Wait()
	if err != nil {
		log.Println(args[0], err)
	}
}
