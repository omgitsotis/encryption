package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

// Client provides functionality to interact with the encryption-server
type Client interface {
	// Store accepts an id and a payload in bytes and requests that the
	// encryption-server stores them in its data store
	Store(id, payload []byte) (aesKey []byte, err error)

	// Retrieve accepts an id and an AES key, and requests that the
	// encryption-server retrieves the original (decrypted) bytes stored
	// with the provided id
	Retrieve(id, aesKey []byte) (payload []byte, err error)
}

// EncryptionClient is an implentation of the Client interface
type EncryptionClient struct{}

// Store accepts an id and a payload in bytes and requests that the
// encryption-server stores them in its data store
func (c *EncryptionClient) Store(id, payload []byte) (aesKey []byte, err error) {
	aesKey = make([]byte, 32)
	if _, err = rand.Read(aesKey); err != nil {
		fmt.Println("error creating private key: ", err.Error())
		return
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	b := base64.StdEncoding.EncodeToString(payload)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))

	ioutil.WriteFile(string(id), []byte(ciphertext), 777)
	return
}

// Retrieve accepts an id and an AES key, and requests that the
// encryption-server retrieves the original (decrypted) bytes stored
// with the provided id
func (c *EncryptionClient) Retrieve(id, aesKey []byte) (payload []byte, err error) {
	text, err := ioutil.ReadFile(string(id))
	if err != nil {
		return nil, err
	}

	if text == nil {
		return nil, errors.New("entry for ID not found")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := text[:aes.BlockSize]
	src := text[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(src, src)

	data, err := base64.StdEncoding.DecodeString(string(src))
	if err != nil {
		return nil, err
	}

	return data, nil
}
