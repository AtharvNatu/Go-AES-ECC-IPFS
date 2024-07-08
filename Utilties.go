package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
)

// Converts input password into SHA-256 hash and returns slice according to AesKeyLength
func getSymmetricKey(password string) []byte {
	// Code
	hash := sha256.New()
	hash.Write([]byte(password))
	passwordHash := hash.Sum(nil)
	switch AesKeyLength {
	case 128:
		return passwordHash[0:16]
	case 256:
		return passwordHash
	}
	return nil
}

// Converts input password into SHA-256 hash and returns 16 byte key
func getHybridKey(password string) []byte {
	// Code
	hash := sha256.New()
	hash.Write([]byte(password))
	passwordHash := hash.Sum(nil)
	return passwordHash[0:16]
}

// Generates Random IV of 16 bytes
func getIV() ([]byte, error) {
	// Code
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

// Pads the input slice to a multiple of blockSize using PKCS#7 padding
func addPadding(input []byte, blockSize int) []byte {
	// Code
	padding := blockSize - (len(input) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(input, padText...)
}

// Removes PKCS#7 padding from the input slice
func removePadding(input []byte) ([]byte, error) {
	// Code
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}

	padding := int(input[len(input)-1])
	if padding <= 0 || padding > len(input) {
		return nil, errors.New("invalid padding")
	}

	for i := len(input) - padding; i < len(input); i++ {
		if int(input[i]) != padding {
			return nil, errors.New("invalid padding")
		}
	}

	return input[:len(input)-padding], nil
}

func checkKeyFile(fileName string) bool {

	// Code
	_, err := os.Stat(fileName)

	if os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
