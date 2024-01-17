package winssh

import (
	"fmt"
	"log"
	"os"
	"path"
	"runtime"

	"github.com/xlab/closer"
)

const (
	ansiReset     = "\u001B[0m"
	ansiRedBGBold = "\u001B[41m\u001B[1m"
	BUG           = "Ж"
)

var (
	letf = log.New(os.Stdout, BUG, log.Ltime|log.Lshortfile)
	let  = log.New(os.Stdout, BUG, log.Ltime)
	ltf  = log.New(os.Stdout, " ", log.Ltime|log.Lshortfile)
	lt   = log.New(os.Stdout, " ", log.Ltime)
)

// Get source of code
func src() (s string) {
	pc := make([]uintptr, 1)
	n := runtime.Callers(3, pc)
	if n > 0 {
		frame, _ := runtime.CallersFrames(pc).Next()
		s = fmt.Sprintf("%s:%d:", path.Base(frame.File), frame.Line)
	}
	return
}

func Println(v ...any) (ok bool) {
	anys := []any{src()}
	ok = true
	for _, a := range v {
		switch t := a.(type) {
		case nil:
			anys = append(anys, "Ф")
		case error:
			anys = append(anys, t)
			ok = false
		case string:
			if t != "" {
				anys = append(anys, t)
			}
		default:
			anys = append(anys, t)
		}
	}
	if ok {
		lt.Println(anys...)
	} else {
		let.Println(anys...)
	}
	return ok
}
func Fatal(err error) {
	if err != nil {
		let.Println(src(), err)
		closer.Exit(1)
	}
}
func FatalOr(s string, cases ...bool) {
	for _, c := range cases {
		if c {
			let.Println(src(), s)
			closer.Exit(1)
			break
		}
	}
}
func FatalAnd(s string, cases ...bool) {
	for _, c := range cases {
		if !c {
			return
		}
	}
	let.Println(src(), s)
	closer.Exit(1)
}
