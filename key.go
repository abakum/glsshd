package winssh

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"

	gl "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

const (
	sshHostKey                   = "ssh_host_rsa_key"               // OpenSSH for Windows
	administratorsAuthorizedKeys = "administrators_authorized_keys" // OpenSSH for Windows
	authorizedKeys               = "authorized_keys"                // write from embed or from first client
)

var aKeyPath string

// like gl.GenerateSigner plus write key to files
func GenerateSigner(pri string) (gl.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	Bytes := x509.MarshalPKCS1PrivateKey(key)
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: Bytes,
	})
	os.WriteFile(pri, data, 0644)

	Bytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err == nil {
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: Bytes,
		})

		os.WriteFile(pri+".pub", data, 0644)
	}

	return ssh.NewSignerFromKey(key)
}

// ParseAuthorizedKeys
func FileToAuthorized(bs []byte, err error) (authorized []gl.PublicKey) {
	if err != nil {
		return
	}
	for _, b := range bytes.Split(bs, []byte("\n")) {
		k, _, _, _, err := gl.ParseAuthorizedKey(b)
		if err == nil {
			log.Println("FileToAuthorized", string(b))
			authorized = append(authorized, k)
		}
	}
	return
}

// case no files then write from embed
func BytesToAuthorized(authorized_keys []byte, old []gl.PublicKey) (authorized []gl.PublicKey) {
	authorized = old
	if len(old) > 0 || len(authorized_keys) == 0 {
		return
	}
	log.Println("BytesToAuthorized")
	authorized = FileToAuthorized(authorized_keys, nil)
	if len(authorized) > 0 {
		file := filepath.Join(aKeyPath, authorizedKeys)
		log.Println("WriteFile", file)
		os.WriteFile(file, authorized_keys, 0644)
		return
	}
	return old
}

// case no files and not embed then write from first client
func KeyToAuthorized(key gl.PublicKey, old []gl.PublicKey) []gl.PublicKey {
	if len(old) > 0 {
		return old
	}
	// only first login
	b := ssh.MarshalAuthorizedKey(key)
	log.Println("KeyToAuthorized", string(b))
	return BytesToAuthorized(b, old)
}

// is autorized
func Authorized(key gl.PublicKey, authorized []gl.PublicKey) bool {
	for _, k := range authorized {
		if gl.KeysEqual(key, k) {
			return true
		}
	}
	return false
}

// get allowed keys
func GetUserKeys(cwd string) (authorized []gl.PublicKey) {
	aKeyPath = cwd //.ssh
	for _, akf := range GetUserKeysPaths(cwd) {
		log.Println(akf)
		kk := FileToAuthorized(os.ReadFile(akf))
		authorized = append(authorized, kk...)
	}
	return
}
