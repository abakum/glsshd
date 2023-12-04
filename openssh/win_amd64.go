//go:build windows && amd64
// +build windows,amd64

package openssh

import (
	"embed"
)

//go:embed amd64/*
var bin embed.FS
