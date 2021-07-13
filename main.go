package main

import (
  "bytes"
  "bufio"
	"crypto/aes"
	"crypto/sha256"
	"crypto/cipher"
	"crypto/rand"
  "encoding/base64"
  "flag"
	"fmt"
	"io"
  "io/ioutil"
  "os"
  "golang.org/x/crypto/pbkdf2"
)

var (
  iterations=1  // lame
  keyLen=32
  nonceLen=16   // non-standard
  salt=[]byte("disk-encryption") // static salt
  debug=false
  flgSplunkSecretFile = flag.String("splunk.secret","/opt/splunk/etc/auth/splunk.secret","path to splunk-secret file")
  flgDecrypt = flag.Bool("decrypt",false,"decrypt")
)

func getSplunkSecret(path string) ([]byte, error) {
  return ioutil.ReadFile(path)
}

func EncryptSplunk(password []byte, plaintext []byte) ([]byte, error) {

  // all this does is take the splunk secret, with is static
  // and creates a secure key to do the actual encryption with
  dk := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

  // now we generate a nonce and feed it into a GCM
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, nonceLen)
	if err != nil {
    return nil, err
	}

  // encrypt
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

  if debug {
    fmt.Println("encryption nonce :")
    fmt.Println(nonce)
    fmt.Println("encryption ciphertext :")
    fmt.Println(ciphertext)
  }

  // base64 encode the nonce + encrypted text
  // and stick $7$ in front
  buf := bytes.Buffer{}
  buf.Write([]byte("$7$"))
  encoder := base64.NewEncoder(base64.StdEncoding, &buf)
  encoder.Write(append(nonce, ciphertext...))
  encoder.Close()

  return buf.Bytes(),nil

}

func DecryptSplunk (password []byte, encryptedBytes []byte) ([]byte, error) {

  // all this does is take the splunk secret, with is static
  // and creates a secure key to do the actual encryption with
  dk := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

  // remove $7$
  encryptedBytes = encryptedBytes[3:]

  // base64decode
  bytes, err := base64.StdEncoding.DecodeString(string(encryptedBytes))
  if err != nil {
    return nil,err
  }

  // nonce is 1st 16 bytes, ciphertext is the rest
  nonce := bytes[0:16]
  ciphertext := bytes[16:]

  if debug {
    fmt.Println("decryption nonce :")
    fmt.Println(nonce)
    fmt.Println("decryption ciphertext :")
    fmt.Println(ciphertext)
  }

  // construct the decoder
	aesgcm, err := cipher.NewGCMWithNonceSize(block, nonceLen)
	if err != nil {
    return nil, err
	}

  // decode
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func main() {

  flag.Parse()
  splunkSecret, err := getSplunkSecret(*flgSplunkSecretFile)
  if err !=nil {
    panic(err.Error())
  }
  // splunk secret should be 254 bytes long. hours !!!
  splunkSecret=splunkSecret[0:254]

  reader := bufio.NewReader(os.Stdin)
  input, _ := reader.ReadBytes('\n')

  output := []byte("")
  if *flgDecrypt == true {
    //decrypt
    output, err = DecryptSplunk(splunkSecret, input)
    if err!=nil {
      panic(err.Error())
    }
  } else {
    // encrypt
    output, err = EncryptSplunk(splunkSecret, []byte("lala"))
    if err != nil {
      panic(err.Error())
    }
  }
  fmt.Println(string(output))

}
