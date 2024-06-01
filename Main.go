package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

// Generate ECC key pair
func generateKeyPair() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// Derive shared secret using ECDH
func deriveSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	hash := sha256.Sum256(x.Bytes())
	return hash[:], nil
}

// Encrypt file using AES
func encryptFile(key []byte, inputFile, outputFile string) error {
	plaintext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ioutil.WriteFile(outputFile, ciphertext, 0644)
}

// Decrypt file using AES
func decryptFile(key []byte, inputFile, outputFile string) error {
	ciphertext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := ciphertext[:aes.BlockSize]
	plaintext := make([]byte, len(ciphertext[aes.BlockSize:]))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return ioutil.WriteFile(outputFile, plaintext, 0644)
}

func main() {
	// Generate ECC key pairs for Alice and Bob
	alicePrivKey, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Error generating Alice's key pair: %v", err)
	}
	bobPrivKey, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Error generating Bob's key pair: %v", err)
	}

	// Derive shared secret
	aliceSharedSecret, err := deriveSharedSecret(alicePrivKey, &bobPrivKey.PublicKey)
	if err != nil {
		log.Fatalf("Error deriving Alice's shared secret: %v", err)
	}
	bobSharedSecret, err := deriveSharedSecret(bobPrivKey, &alicePrivKey.PublicKey)
	if err != nil {
		log.Fatalf("Error deriving Bob's shared secret: %v", err)
	}

	// Ensure the derived shared secrets are equal
	if !equal(aliceSharedSecret, bobSharedSecret) {
		log.Fatalf("Shared secrets do not match!")
	}

	// File paths
	inputFile := "input.txt"
	encryptedFile := "encrypted.dat"
	decryptedFile := "decrypted.txt"

	// Encrypt the file using the shared secret
	err = encryptFile(aliceSharedSecret, inputFile, encryptedFile)
	if err != nil {
		log.Fatalf("Error encrypting file: %v", err)
	}
	fmt.Println("File encrypted successfully.")

	// Decrypt the file using the shared secret
	err = decryptFile(bobSharedSecret, encryptedFile, decryptedFile)
	if err != nil {
		log.Fatalf("Error decrypting file: %v", err)
	}
	fmt.Println("File decrypted successfully.")
}

// Helper function to compare byte slices
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
