package main

import (
	"fmt"
)

var password = "12345678"
var inputFile = "/home/atharv/Desktop/Projects/IPFS/Data/Novel.txt"
var encryptedFile = "/home/atharv/Desktop/Projects/IPFS/Data/Novel.txt.enc"
var decryptedFile = "/home/atharv/Desktop/Projects/IPFS/Data/Novel_new.txt"

func runAES() {
	// Code

	// AES 256-bit
	aesKey := getSymmetricKey(password)

	fmt.Printf("\nTime to Encrypt using AES 256-bit Encryption : %s\n", AESEncrypt(inputFile, encryptedFile, aesKey))
	fmt.Printf("\nTime to Decrypt using AES 256-bit Decryption : %s\n", AESDecrypt(encryptedFile, decryptedFile, aesKey))
}

func runHybridAESECC() {
	// Code

	// AES 128-bit key
	aesKey := getHybridKey(password)

	//// Init ECC
	//eccPrivateKey := generateECCKeyPair()
	//
	//savePrivateKey(eccPrivateKey)
	//savePublicKey(eccPrivateKey.PublicKey)

	// Receiver's Public Key
	receiverPublicKey := loadPublicKey("public_key.crt")

	// Receiver's Private Key
	receiverPrivateKey := loadPrivateKey("private_key.crt")

	fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))
	fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt(encryptedFile, decryptedFile, receiverPrivateKey))
}

func hybridEncryptAndUpload() {

	// Code

	// AES 128-bit key
	aesKey := getHybridKey(password)

	// Receiver's Public Key
	receiverPublicKey := loadPublicKey("public_key.crt")

	fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))

	fmt.Printf("\nCID : %s\n", uploadToIPFS(encryptedFile))
}

func hybridDownloadAndDecrypt() {

	// Code

	downloadFromIPFS("/home/atharv/Desktop/download", "QmcoXqGpEYo5Y5gYixK94eMHX4MziYi3wKQCL2y6aoNUG5")

	// Receiver's Private Key
	receiverPrivateKey := loadPrivateKey("private_key.crt")

	fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt("/home/atharv/Desktop/download", "/home/atharv/Desktop/decrypted.txt", receiverPrivateKey))
}

func main() {

	//runAES()

	//runHybridAESECC()

	//hybridEncryptAndUpload()

	hybridDownloadAndDecrypt()
}
