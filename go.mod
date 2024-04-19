module github.com/abakum/winssh

go 1.21.4

// replace github.com/abakum/go-console => ../go-console

require (
	github.com/Microsoft/go-winio v0.6.1
	github.com/abakum/go-ansiterm v0.0.0-20240209124652-4fc46d492442
	github.com/abakum/go-console v0.0.0-20240401135801-ff2ca721c6ad
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/gliderlabs/ssh v0.3.5
	github.com/pkg/sftp v1.13.6
	github.com/xlab/closer v1.1.0
	github.com/zzl/go-win32api/v2 v2.1.0
	golang.org/x/crypto v0.19.0
)

require (
	github.com/abakum/embed-encrypt v0.0.0-20240330115809-059354cfa29a // indirect
	github.com/creack/pty v1.1.21 // indirect
	github.com/iamacarpet/go-winpty v1.0.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/stretchr/testify v1.8.1 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/tools v0.16.0 // indirect
)
