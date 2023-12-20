package main

import (
	"fmt"
)

var password = "12345678"
var inputFile = "/home/atharv/Desktop/IPFS-Data/Novel.txt"
var encryptedFile = "/home/atharv/Desktop/IPFS-Data/Novel.txt.enc"
var decryptedFile = "/home/atharv/Desktop/IPFS-Data/Novel_IPFS_Decrypted.txt"

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

func hybridEncryptAndUpload() string {

	// Code

	// AES 128-bit key
	aesKey := getHybridKey(password)

	// Receiver's Public Key
	receiverPublicKey := loadPublicKey("public_key.crt")

	fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))

	cid := uploadToIPFS(encryptedFile)
	fmt.Printf("\nCID : %s\n", cid)

	return cid
}

func hybridDownloadAndDecrypt(inputFile string, cid string) {

	// Code

	downloadFromIPFS(inputFile, cid)

	// Receiver's Private Key
	receiverPrivateKey := loadPrivateKey("private_key.crt")

	fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt(inputFile, decryptedFile, receiverPrivateKey))
}

func main() {

	//// Init ECC
	//eccPrivateKey := generateECCKeyPair()
	//
	//savePrivateKey(eccPrivateKey)
	//savePublicKey(eccPrivateKey.PublicKey)

	//runAES()

	//runHybridAESECC()

	cid := hybridEncryptAndUpload()

	hybridDownloadAndDecrypt("/home/atharv/Desktop/IPFS-Data/Encrypted-Novel-File", cid)
}
