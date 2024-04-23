//go:build windows
// +build windows

package openssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/abakum/go-console"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/zzl/go-win32api/v2/win32"
)

const (
	shellhost = "ssh-shellhost.exe"
	M77       = time.Millisecond * 77
	BIN       = "OpenSSH"
	ansiReset = "\u001B[0m"
	ansiRedBG = "\u001B[41m"
	BUG       = ansiRedBG + "Ж" + ansiReset
)

var (
	letf = log.New(os.Stdout, BUG, log.Ltime|log.Lshortfile)
	ltf  = log.New(os.Stdout, " ", log.Ltime|log.Lshortfile)
)

// copy from embed
func UnloadEmbedded(src, root, trg string, keep bool) error {
	// keep == true if not exist then write
	// keep == false it will be replaced if it differs from the embed

	ltf.Println("UnloadEmbedded")
	srcLen := len(strings.Split(src, "/"))
	dirs := append([]string{root}, strings.Split(trg, `\`)...)
	write := func(unix string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		win := filepath.Join(append(dirs, strings.Split(unix, "/")[srcLen:]...)...)
		if d.IsDir() {
			_, err = os.Stat(win)
			if err != nil {
				err = os.MkdirAll(win, 0755)
			}
			return err
		}
		bytes, err := bin.ReadFile(unix)
		if err != nil {
			return err
		}
		var size int64
		fi, err := os.Stat(win)
		if err == nil {
			size = fi.Size()
			if int64(len(bytes)) == size || keep {
				return nil
			}
		}
		ltf.Println(win, len(bytes), "->", size)
		return os.WriteFile(win, bytes, 0644)
	}
	return fs.WalkDir(fs.FS(bin), src, write)
}

var once sync.Once

// PTY from OpenSSH
func ShellArgs(commands []string) (args []string) {
	once.Do(func() {
		UnloadEmbedded(runtime.GOARCH, console.UsrBin(), BIN, false)
	})

	path := ""
	var err error
	for _, shell := range []string{
		filepath.Join(console.UsrBin(), BIN, shellhost),
		filepath.Join(os.Getenv("ProgramFiles"), BIN, shellhost),
	} {
		if path, err = exec.LookPath(shell); err == nil {
			break
		}
	}
	if err != nil { //fallback
		return commands
	}
	args = []string{path}
	opt := "-c"
	shell := len(commands) == 1
	if shell {
		opt = "---pty"
	}
	args = append(args, opt)
	args = append(args, commands...)
	return
}

// PTY from OpenSSH
// amd64 to handle winCh over ctderr
// 386 ugly to handle winCh by `mod con columns=`
func OpenSshPTY(s gl.Session) {
	args, cmdLine := winssh.ShArgs(s)
	e := winssh.Env(s, args[0])
	args = ShellArgs(args)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = winssh.Home(s)
	cmd.Env = append(os.Environ(), e...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		letf.Println("unable to open stdout pipe", err)
		winssh.NoPTY(s)
		return
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		letf.Println("unable to open stdin pipe", err)
		winssh.NoPTY(s)
		return
	}

	cmdErr, tty, err := os.Pipe()
	if err != nil {
		letf.Println("unable to open stderr pipe", err)
		winssh.NoPTY(s)
		return
	}
	defer cmdErr.Close()
	defer tty.Close()
	cmd.Stderr = cmdErr // use cmdErr for tty

	err = cmd.Start()
	if err != nil {
		letf.Println("unable to start", cmdLine, err)
		winssh.NoPTY(s) // fallback
		return
	}

	ppid := cmd.Process.Pid
	ltf.Println(cmdLine, ppid)
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
				ltf.Println(hwnd, GetWindowText(hwnd), GetClassName(hwnd))
				return 0
			}
			return 1
		}
		win32.EnumWindows(syscall.NewCallback(hide), 0)
	}
	ltf.Println(cmdPID, cmdHWND)
	ptyReq, winCh, _ := s.Pty()
	var Width int
	SetSize := func(tty, in io.Writer, win gl.Window) error {
		if win.Height == 0 && win.Width == 0 {
			return fmt.Errorf("0x0")
		}
		if Width == win.Width {
			return nil
		}
		shrink := Width > win.Width
		Width = win.Width
		ltf.Println("PTY SetSize", win)
		//https://github.com/PowerShell/openssh-portable/blob/4ee8dc64982b62cd520417556515383908091b76/contrib/win32/win32compat/shell-host.c#L804
		if runtime.GOARCH == "amd64" {
			//https://github.com/PowerShell/Win32-OpenSSH/issues/1222#issuecomment-409052375
			const PTY_SIGNAL_RESIZE_WINDOW uint16 = 8 //https://github.com/PowerShell/openssh-portable/blob/cb23f0d9c0f4d40edbc2863419dcff40ebd5e0a6/contrib/win32/win32compat/misc_internal.h#L32C9-L32C33
			buf := new(bytes.Buffer)
			signalPacket := []uint16{PTY_SIGNAL_RESIZE_WINDOW, uint16(win.Width), uint16(win.Height)}
			err := binary.Write(buf, binary.LittleEndian, signalPacket)
			if err != nil {
				letf.Println(err)
			}
			n, err := tty.Write(buf.Bytes())
			if n != 6 || err != nil {
				letf.Println(err)
			}
		} else {
			if shrink {
				fmt.Fprintf(in, "mode")
				fmt.Fprintf(in, " con")
				fmt.Fprintf(in, " cols=%d\n", win.Width-1)
			}
			fmt.Fprintf(in, "mode")
			fmt.Fprintf(in, " con")
			fmt.Fprintf(in, " cols=%d\n", win.Width)
		}
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
	ltf.Println(cmdLine, "done")
}

// create buffer for string
func BufToPwstr(size uint) *uint16 {
	buf := make([]uint16, size*2+1)
	return &buf[0]
}

// get class name by hwnd
func GetClassName(hwnd win32.HWND) (ClassName string) {
	const nMaxCount = 256

	if hwnd == 0 {
		return
	}

	lpClassName := BufToPwstr(nMaxCount)
	copied, er := win32.GetClassName(hwnd, lpClassName, nMaxCount)
	if copied == 0 || er != win32.NO_ERROR {
		return
	}
	ClassName = win32.PwstrToStr(lpClassName)
	return
}

// get title of window by hwnd
func GetWindowText(hwnd win32.HWND) (WindowText string) {
	const nMaxCount = 256

	if hwnd == 0 {
		return
	}

	lpString := BufToPwstr(nMaxCount)
	copied, er := win32.GetWindowText(hwnd, lpString, nMaxCount)
	if copied == 0 || er != win32.NO_ERROR {
		return
	}
	WindowText = win32.PwstrToStr(lpString)
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
