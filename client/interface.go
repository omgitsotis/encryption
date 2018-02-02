package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"fmt"
	"errors"
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

type EncryptionClient struct {
	Storage map[string][]byte
}

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
    
  	c.Storage[string(id)] = ciphertext

	return
}

func (c *EncryptionClient) Retrieve(id, aesKey []byte) (payload []byte, err error) {
	var text []byte
	text = c.Storage[string(id)]
	fmt.Printf("storge %v\n", c.Storage)
	
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
    fmt.Printf("storge %v\n", c.Storage)
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(src, src)
    fmt.Printf("storge %v\n", c.Storage)
    data, err := base64.StdEncoding.DecodeString(string(src))
    if err != nil {
        return nil, err
    }
    fmt.Printf("storge %v\n", c.Storage)
    return data, nil
}

//entry_2 JLk3oMYSWfSqhHKQ/fqqBfnC1vUAYUN2BpnNy58zlC4=