// spy
package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/xlab/closer"
)

const shellhost = "ssh-shellhost.exe"

func main() {
	defer closer.Close()

	dir := filepath.Join(os.Getenv("ALLUSERSPROFILE"), "ssh")
	cmd := exec.Command(filepath.Join(dir, shellhost), os.Args[1:]...)

	ferr, err := os.Create(filepath.Join(dir, "err"))
	if err != nil {
		log.Fatal(err)
	}
	defer ferr.Close()
	log.SetOutput(ferr)
	log.Println(cmd.Args)

	// Attach STDOUT stream
	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	fo, err := os.Create(filepath.Join(dir, "fo"))
	if err != nil {
		log.Fatal(err)
	}
	defer fo.Close()

	// Attach STDIN stream
	cmdIn, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
		return
	}
	fi, err := os.Create(filepath.Join(dir, "fi"))
	if err != nil {
		log.Fatal(err)
	}
	defer fi.Close()

	fe, err := os.Create(filepath.Join(dir, "fe"))
	if err != nil {
		log.Fatal(err)
	}
	defer fe.Close()

	// Spawn go-routine to copy os's stdin to command's stdin and fi
	go io.Copy(io.MultiWriter(cmdIn, fi), os.Stdin)

	// Spawn go-routine to copy command's stdout to os's stdout and fo
	go io.Copy(io.MultiWriter(os.Stdout, fo), cmdOut)

	pr, pw, err := os.Pipe()
	if err != nil {
		log.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	cmd.Stderr = pr // use cmdErr for input

	// Spawn go-routine to copy os's stderr to command's stderr and fe
	go io.Copy(io.MultiWriter(pw, fe), os.Stderr)

	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	// in fe I find
	// cols120_rows45 := []byte{8, 0, 120, 0, 45, 0}

}
