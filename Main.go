package main

import (
	"fmt"
)

func runAES() {
	// Code
	var password = "12345678"
	var inputFile = "/home/atharv/Desktop/Projects/IPFS/Data/Ventura.bmp"
	var encryptedFile = "/home/atharv/Desktop/Projects/IPFS/Data/Ventura.bmp.enc"
	var decryptedFile = "/home/atharv/Desktop/Projects/IPFS/Data/Ventura_DECR.bmp"

	// AES 256-bit
	aesKey := getSymmetricKey(password)

	fmt.Printf("\nTime to Encrypt using AES 256-bit Encryption : %s\n", AESEncrypt(inputFile, encryptedFile, aesKey))
	fmt.Printf("\nTime to Decrypt using AES 256-bit Decryption : %s\n", AESDecrypt(encryptedFile, decryptedFile, aesKey))
}

func runHybridAESECC() {
	// Code
	var password = "12345678"
	var inputFile = "/home/atharv/Desktop/Projects/IPFS/Data/Ventura.bmp"
	var encryptedFile = "/home/atharv/Desktop/Projects/IPFS/Data/Ventura.bmp.enc"
	var decryptedFile = "/home/atharv/Desktop/Projects/IPFS/Data/Ventura_DECR.bmp"

	// AES 128-bit key
	aesKey := getHybridKey(password)

	// Init ECC
	eccPrivateKey := generateECCKeyPair()

	savePrivateKey(eccPrivateKey)
	savePublicKey(eccPrivateKey.PublicKey)

	// Receiver's Public Key
	receiverPublicKey := loadPublicKey("public_key.crt")

	// Receiver's Private Key
	receiverPrivateKey := loadPrivateKey("private_key.crt")

	fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))
	fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt(encryptedFile, decryptedFile, receiverPrivateKey))
}

func main() {

	runAES()

	runHybridAESECC()
}