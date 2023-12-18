package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	eciesgo "github.com/ecies/go"
	"os"
	"time"
)

// AesEccEncrypt Encrypts the file using AES 128-bit CBC Mode Encryption along with ECC
func AesEccEncrypt(inputFile string, outputFile string, encryptionKey []byte, publicKey *eciesgo.PublicKey) time.Duration {

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

	// Encrypt the AES Key with ECC public key
	encryptedAESKey, err := eciesgo.Encrypt(publicKey, encryptionKey)
	if err != nil {
		fmt.Printf("Error Occurred While Encrypting AES Encryption Key : %s\n", err)
		return -1
	}

	// Create AES Block Cipher
	blockCipher, err := aes.NewCipher(encryptionKey)
	if err != nil {
		fmt.Printf("Error Occurred While Creating AES Block Cipher For Encryption : %s\n", err)
		return -1
	}

	// Pad Plaintext using PKCS#7 padding
	plaintext = addPadding(plaintext, aes.BlockSize)

	// Create new AES block cipher with CBC (Cipher Block Chaining)
	cbcEncrypt := cipher.NewCBCEncrypter(blockCipher, iv)

	// Create Ciphertext buffer
	ciphertext := make([]byte, len(plaintext))

	// Encrypt Plaintext
	cbcEncrypt.CryptBlocks(ciphertext, plaintext)

	// Combine Encrypted Content for storage
	output := append(iv, encryptedAESKey...)
	output = append(output, ciphertext...)

	elapsedTime := time.Since(startTime)

	// Write encrypted data to output file
	err = os.WriteFile(outputFile, output, 0644)
	if err != nil {
		fmt.Printf("Error Occurred While Writing To Encrypted Output File : %s\n", err)
		return -1
	}

	return elapsedTime
}

// AesEccDecrypt Decrypts the file using AES 128-bit CBC Mode Decryption along with ECC
func AesEccDecrypt(inputFile string, outputFile string, privateKey *eciesgo.PrivateKey) time.Duration {

	// Code

	// Read Encrypted File
	encryptedData, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error Occurred While Reading Encrypted Input File : %s\n", err)
		return -1
	}

	startTime := time.Now()

	// Extract IV and Encrypted AES Key
	iv := encryptedData[:aes.BlockSize]
	encryptedAESKey := encryptedData[aes.BlockSize:(ECCKeyLength + aes.BlockSize)]

	// Decrypt the AES Key with ECC private key
	decryptedAESKey, err := eciesgo.Decrypt(privateKey, encryptedAESKey)
	if err != nil {
		fmt.Printf("Error Occurred While Decrypting AES Decryption Key : %s\n", err)
		return -1
	}

	// Create AES Cipher Block
	block, err := aes.NewCipher(decryptedAESKey)
	if err != nil {
		fmt.Printf("Error Occurred While Creating AES Block Cipher For Decryption : %s\n", err)
		return -1
	}

	// Create new AES block cipher with CBC (Cipher Block Chaining)
	cbcDecrypt := cipher.NewCBCDecrypter(block, iv)

	// Create Plaintext buffer
	ciphertext := encryptedData[aes.BlockSize+ECCKeyLength:]
	plaintext := make([]byte, len(ciphertext))

	// Decrypt Ciphertext
	cbcDecrypt.CryptBlocks(plaintext, ciphertext)

	// Remove padding from plaintext
	plaintext, err = removePadding(plaintext)
	if err != nil {
		fmt.Printf("Error Occurred While Removing Padding : %s\n", err)
		return -1
	}

	elapsedTime := time.Since(startTime)

	// Write decrypted data to output file
	err = os.WriteFile(outputFile, plaintext, 0644)
	if err != nil {
		fmt.Printf("Error Occurred While Writing To Decrypted Output File : %s\n", err)
		return -1
	}

	return elapsedTime
}
