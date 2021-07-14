package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

var (
	iterations          = 1
	keyLen              = 32
	nonceLen            = 16                        // non-standard
	salt                = []byte("disk-encryption") // static salt
	flgSplunkSecretFile = flag.String("splunk.secret", "/opt/splunk/etc/auth/splunk.secret", "path to splunk-secret file")
	flgDecrypt          = flag.Bool("decrypt", false, "decrypt")
	flgDebug            = flag.Bool("debug", false, "debug")
)

func getSplunkSecret(path string) ([]byte, error) {
	splunkSecret, err := ioutil.ReadFile(path)
	if err != nil {
		return []byte(""), err
	}
	splunkSecret = bytes.TrimRight(splunkSecret, "\r\n")
	if len(splunkSecret) != 254 {
		return []byte(""), fmt.Errorf("SplunkSecret is not 254 bytes long")
	}
	return splunkSecret, nil
}

func newGCM(password []byte) (cipher.AEAD, error) {
	// all this does is take the splunk secret, with is static
	// and creates a secure key to do the actual encryption with
	dk := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCMWithNonceSize(block, nonceLen)
}

func EncryptSplunk(password []byte, plaintext []byte, debug bool) ([]byte, error) {

	aesgcm, err := newGCM(password)
	if err != nil {
		return nil, err
	}

	// now we generate a nonce and feed it into a GCM
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// encrypt
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	if debug {
		fmt.Fprintf(os.Stderr, "     nonce : %v\nciphertext : %v\n", nonce, ciphertext)
	}

	// base64 encode the nonce + encrypted text
	// and stick $7$ in front
	buf := bytes.Buffer{}
	buf.Write([]byte("$7$"))
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write(append(nonce, ciphertext...))
	encoder.Close()

	return buf.Bytes(), nil

}

func isPiped() bool {
	fi, _ := os.Stdin.Stat()
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func DecryptSplunk(password []byte, encryptedBytes []byte, debug bool) ([]byte, error) {

	if string(encryptedBytes[0:3]) != "$7$" {
		return nil, fmt.Errorf("Invalid string to decrypt")
	}

	aesgcm, err := newGCM(password)
	if err != nil {
		return nil, err
	}

	// remove $7$
	encryptedBytes = encryptedBytes[3:]

	// base64decode
	bytes, err := base64.StdEncoding.DecodeString(string(encryptedBytes))
	if err != nil {
		return nil, err
	}

	// nonce is 1st 16 bytes, ciphertext is the rest
	nonce := bytes[0:16]
	ciphertext := bytes[16:]

	if debug {
		fmt.Fprintf(os.Stderr, "     nonce : %v\nciphertext : %v\n", nonce, ciphertext)
	}

	// decode
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func main() {

	flag.Parse()
	splunkSecret, err := getSplunkSecret(*flgSplunkSecretFile)
	if err != nil {
		panic(err.Error())
	}

	if !isPiped() {
		fmt.Printf("Enter text : ")
	}

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadBytes('\n')

	output := []byte("")
	if *flgDecrypt == true {
		output, err = DecryptSplunk(splunkSecret, input, *flgDebug)
	} else {
		output, err = EncryptSplunk(splunkSecret, input, *flgDebug)
	}

	if err != nil {
		panic(err.Error())
	}

	fmt.Println(string(output))

}
