// from github.com/gliderlabs/ssh

package winssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/anmitsu/go-shlex"
	gl "github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	AgentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"
	maxSigBufSize    = 128
)

// SubsystemHandlerSftp for sftp
func SubsystemHandlerSftp(s gl.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		s,
		serverOptions...,
	)
	if err != nil {
		fmt.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		fmt.Println("sftp client exited session.")
	} else if err != nil {
		fmt.Println("sftp server completed with error:", err)
	}
}

func SessionHandler(srv *gl.Server, conn *ssh.ServerConn, newChan ssh.NewChannel, ctx gl.Context) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		// TODO: trigger event callback
		return
	}
	sess := &session{
		Channel:           ch,
		conn:              conn,
		handler:           srv.Handler,
		ptyCb:             srv.PtyCallback,
		sessReqCb:         srv.SessionRequestCallback,
		subsystemHandlers: srv.SubsystemHandlers,
		ctx:               ctx,
	}
	sess.handleRequests(reqs)
}

type session struct {
	sync.Mutex
	ssh.Channel
	conn              *ssh.ServerConn
	handler           gl.Handler
	subsystemHandlers map[string]gl.SubsystemHandler
	handled           bool
	exited            bool
	pty               *gl.Pty
	winch             chan gl.Window
	env               []string
	ptyCb             gl.PtyCallback
	sessReqCb         gl.SessionRequestCallback
	rawCmd            string
	subsystem         string
	ctx               gl.Context
	sigCh             chan<- gl.Signal
	sigBuf            []gl.Signal
	breakCh           chan<- bool
}

func (sess *session) Write(p []byte) (n int, err error) {
	if sess.pty != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// this is a hardcoded shortcut since we don't support terminal modes.
		p = bytes.Replace(p, []byte{'\n'}, []byte{'\r', '\n'}, -1)
		p = bytes.Replace(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'}, -1)
		n, err = sess.Channel.Write(p)
		if n > m {
			n = m
		}
		return
	}
	return sess.Channel.Write(p)
}

func (sess *session) PublicKey() gl.PublicKey {
	sessionkey := sess.ctx.Value(gl.ContextKeyPublicKey)
	if sessionkey == nil {
		return nil
	}
	return sessionkey.(gl.PublicKey)
}

func (sess *session) Permissions() gl.Permissions {
	// use context permissions because its properly
	// wrapped and easier to dereference
	perms := sess.ctx.Value(gl.ContextKeyPermissions).(*gl.Permissions)
	return *perms
}

func (sess *session) Context() gl.Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, ssh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

func (sess *session) User() string {
	return sess.conn.User()
}

func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

func (sess *session) LocalAddr() net.Addr {
	return sess.conn.LocalAddr()
}

func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

func (sess *session) RawCommand() string {
	return sess.rawCmd
}

func (sess *session) Command() []string {
	cmd, _ := shlex.Split(sess.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (sess *session) Subsystem() string {
	return sess.subsystem
}

func (sess *session) Pty() (gl.Pty, <-chan gl.Window, bool) {
	if sess.pty != nil {
		return *sess.pty, sess.winch, true
	}
	return gl.Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- gl.Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		go func() {
			for _, sig := range sess.sigBuf {
				sess.sigCh <- sig
			}
		}()
	}
}

func (sess *session) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

func parsePtyRequest(s []byte) (pty gl.Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	pty = gl.Pty{
		Term: term,
		Window: gl.Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseWinchRequest(s []byte) (win gl.Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = gl.Window{
		Width:  int(width32),
		Height: int(height32),
	}
	return
}
