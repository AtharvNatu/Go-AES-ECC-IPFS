package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// *Generate Key Pair
func generateECDHKeyPair() *ecdsa.PrivateKey {

	// Code
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}

	return privateKey
}

// Save ECDH Private Key
func saveECDHPrivateKey(privateKey *ecdsa.PrivateKey, fileName string) {

	// Code

	// Write Key to File
	privateKeyFile, err := os.Create(fileName + ".key")
	if err != nil {
		fmt.Printf("Error Occurred While Creating File To Save Public Key : %s\n", err)
	}
	defer func(publicKeyFile *os.File) {
		err := publicKeyFile.Close()
		if err != nil {

		}
	}(privateKeyFile)

	// Marshal private key to ASN.1 DER format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Println("Error Marshaling Private Key :", err)
		return
	}

	privateKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		fmt.Printf("Error Occurred While Writing ECDH Private Key : %s\n", err)
	}
}

// Save ECDH Public Key
func saveECDHPublicKey(publicKey *ecdsa.PublicKey, fileName string) {
	// Code

	// Write Key to File
	publicKeyFile, err := os.Create(fileName + ".key")
	if err != nil {
		fmt.Printf("Error Occurred While Creating File To Save Public Key : %s\n", err)
	}
	defer func(publicKeyFile *os.File) {
		err := publicKeyFile.Close()
		if err != nil {

		}
	}(publicKeyFile)

	// Marshal public key to ASN.1 DER format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Println("Error Marshaling Public Key : ", err)
		return
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	err = pem.Encode(publicKeyFile, publicKeyPEM)
	if err != nil {
		fmt.Printf("Error Occurred While Writing ECDH Public Key : %s\n", err)
	}
}

// Load ECDH Public Key
func loadECDHPublicKey(publicKeyFile string) *ecdsa.PublicKey {
	// Code

	// Read the public key file
	publicPemBytes, err := os.ReadFile(publicKeyFile)
	if err != nil {
		fmt.Errorf("Error Occurred While Reading ECDH Public Key : %s\n", err)
		return nil
	}

	pemBlock, _ := pem.Decode(publicPemBytes)
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		fmt.Errorf("Error Occurred While Decoding PEM Block For ECDH Public Key : %s\n", err)
		return nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		fmt.Errorf("Error Occurred While Parsing ECDH Public Key : %s\n", err)
		return nil
	}

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		return publicKey
	default:
		fmt.Errorf("Error : Unknown Key Format : %s\n", err)
		return nil
	}

}

// Load ECDH Private Key
func loadECDHPrivateKey(privateKeyFile string) *ecdsa.PrivateKey {
	// Code

	// Read the prviate key file
	privatePemBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		fmt.Errorf("Error Occurred While Reading ECDH Private Key : %s\n", err)
		return nil
	}

	pemBlock, _ := pem.Decode(privatePemBytes)
	if pemBlock == nil || pemBlock.Type != "EC PRIVATE KEY" {
		fmt.Errorf("Error Occurred While Decoding PEM Block For ECDH Private Key : %s\n", err)
		return nil
	}

	privateKey, _ := x509.ParseECPrivateKey(pemBlock.Bytes)
	if privateKey == nil {
		fmt.Errorf("Error Occurred While Parsing ECDH Private Key : %s\n", err)
		return nil
	}

	return privateKey
}

// Derive Shared Secret using ECDH
func deriveSharedSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) []byte {

	// Code
	x, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	hash := sha256.Sum256(x.Bytes())
	return hash[:]
}

// ! Validate Shared Secret => For Testing Only
func validateSecret(senderSecret []byte, receiverSecret []byte) bool {

	// Code
	if len(senderSecret) != len(receiverSecret) {
		return false
	}

	for i := range senderSecret {
		if senderSecret[i] != receiverSecret[i] {
			return false
		}
	}

	return true
}

// * AesEcdhEncrypt() encrypts the file using AES 128-bit CTR Mode Encryption along with ECDH
func AesEcdhEncrypt(inputFile string, outputFile string, encryptionKey []byte) time.Duration {

	// Code

	// Read input file
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error Occurred While Reading Plain Input File : %s\n", err)
		return -1
	}

	startTime := time.Now()

	// Generate IV
	iv, err := getIV()
	if err != nil {
		fmt.Printf("Error Occurred While Generating IV : %s\n", err)
		return -1
	}

	// Create AES Block Cipher
	blockCipher, err := aes.NewCipher(encryptionKey)
	if err != nil {
		fmt.Printf("Error Occurred While Creating AES Block Cipher For Encryption : %s\n", err)
		return -1
	}

	// Create Ciphertext buffer
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	stream := cipher.NewCTR(blockCipher, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	elapsedTime := time.Since(startTime)

	// Write encrypted data to output file
	err = os.WriteFile(outputFile, ciphertext, 0644)
	if err != nil {
		fmt.Printf("Error Occurred While Writing To Encrypted Output File : %s\n", err)
		return -1
	}

	return elapsedTime
}

// * AesEcdhDecrypt() encrypts the file using AES 128-bit CTR Mode Decryption along with ECDH
func AesEcdhDecrypt(inputFile string, outputFile string, decryptionKey []byte) time.Duration {

	// Code

	// Read Encrypted File
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error Occurred While Reading Encrypted Input File : %s\n", err)
		return -1
	}

	startTime := time.Now()

	// Create AES Cipher Block
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		fmt.Printf("Error Occurred While Creating AES Block Cipher For Decryption : %s\n", err)
		return -1
	}

	iv := ciphertext[:aes.BlockSize]

	plaintext := make([]byte, len(ciphertext[aes.BlockSize:]))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	elapsedTime := time.Since(startTime)

	// Write decrypted data to output file
	err = os.WriteFile(outputFile, plaintext, 0644)
	if err != nil {
		fmt.Printf("Error Occurred While Writing To Decrypted Output File : %s\n", err)
		return -1
	}

	return elapsedTime
}
