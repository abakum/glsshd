package winssh

import (
	"fmt"
	"log"
	"time"

	gl "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// logging sessions
func SessionRequestCallback(s gl.Session, requestType string) bool {
	if s == nil {
		return false
	}
	switch requestType {
	case "shell", "exec":
		ptyReq, _, isPty := s.Pty()
		if isPty {
			log.Println(s.RemoteAddr(), requestType, s.Command(), fmt.Sprintf("%v", ptyReq))
		} else {
			log.Println(s.RemoteAddr(), requestType, s.Command())
		}
	default:
		log.Println(s.RemoteAddr(), requestType)
	}
	return true
}

// callback for agentRequest
// based on github.com/gliderlabs/ssh
func (sess *session) handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				req.Reply(false, nil)
				continue
			}

			sess.handled = true
			req.Reply(true, nil)

			go func() {
				sess.handler(sess)
				sess.Exit(0)
			}()
		case "subsystem":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)

			sess.subsystem = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				req.Reply(false, nil)
				continue
			}

			handler := sess.subsystemHandlers[payload.Value]
			if handler == nil {
				handler = sess.subsystemHandlers["default"]
			}
			if handler == nil {
				req.Reply(false, nil)
				continue
			}

			sess.handled = true
			req.Reply(true, nil)

			go func() {
				handler(sess)
				sess.Exit(0)
			}()
		case "env":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			ssh.Unmarshal(req.Payload, &kv)
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			req.Reply(true, nil)
		case "signal":
			var payload struct{ Signal string }
			ssh.Unmarshal(req.Payload, &payload)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- gl.Signal(payload.Signal)
			} else {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, gl.Signal(payload.Signal))
				}
			}
			sess.Unlock()
		case "pty-req":
			if sess.handled || sess.pty != nil {
				req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			if sess.ptyCb != nil {
				ok := sess.ptyCb(sess.ctx, ptyReq)
				if !ok {
					req.Reply(false, nil)
					continue
				}
			}
			sess.pty = &ptyReq
			sess.winch = make(chan gl.Window, 1)
			sess.winch <- ptyReq.Window
			defer func() {
				// when reqs is closed
				close(sess.winch)
			}()
			req.Reply(ok, nil)
		case "window-change":
			if sess.pty == nil {
				req.Reply(false, nil)
				continue
			}
			win, ok := parseWinchRequest(req.Payload)
			if ok {
				sess.pty.Window = win
				sess.winch <- win
			}
			req.Reply(ok, nil)
		case AgentRequestType:
			// SubsystemHandlers: map[string]gl.SubsystemHandler{
			// 	"sftp":                  winssh.SubsystemHandlerSftp,  // to allow sftp
			// 	winssh.AgentRequestType: winssh.SubsystemHandlerAgent, // to allow agent forwarding
			// },
			if sess.handled || getPipe(sess) != "" {
				req.Reply(false, nil)
				continue
			}

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				req.Reply(false, nil)
				continue
			}

			handler := sess.subsystemHandlers[AgentRequestType]
			if handler == nil {
				req.Reply(false, nil)
				continue
			}

			sess.env = append(sess.env, fmt.Sprintf("%s=%s", SSH_AUTH_SOCK, pipe(sess)))
			req.Reply(true, nil)

			go func() {
				handler(sess)
			}()
			// gl.SetAgentRequested(sess.ctx)
			// req.Reply(true, nil)
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				sess.breakCh <- true
				ok = true
			}
			req.Reply(ok, nil)
			sess.Unlock()
		default:
			// TODO: debug log
			if sess.sessReqCb != nil {
				sess.sessReqCb(sess, req.Type)
			}
			req.Reply(false, nil)
		}
	}
}

func Keepalive(s gl.Session, ClientAliveInterval time.Duration, ServerAliveCountMax int) {
	const name = "keepalive"
	i := ServerAliveCountMax
	t := time.NewTicker(ClientAliveInterval)
	defer t.Stop()
	for {
		if s == nil {
			return
		}
		if i <= 0 || t == nil {
			s.Close()
			return
		}
		select {
		case <-s.Context().Done():
			return
		case <-t.C:
			_, err := s.SendRequest(name, true, nil)
			if err == nil {
				i = ServerAliveCountMax
			} else {
				i--
			}
		}
	}
}
