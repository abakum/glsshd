//go:build windows && 386
// +build windows,386

package winssh

import (
	"embed"
)

//go:embed OpenSSH/386/*
var bin embed.FS
