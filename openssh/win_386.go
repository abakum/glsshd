//go:build windows && 386
// +build windows,386

package openssh

import (
	"embed"
)

//go:embed 386/*
var bin embed.FS
