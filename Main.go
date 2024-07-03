package main

import (
	"fmt"
)

var password = "12345678"

// var inputFile = "Novel.txt"
// var encryptedFile = "Novel.txt.enc"
// var decryptedFile = "Novel_Decrypted.txt"
var inputFile = "C:\\Users\\Atharv\\Desktop\\Data\\50MB.txt"
var encryptedFile = "50MB.txt.enc"
var decryptedFile = "50MB_new.txt"

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
	//saveECCPrivateKey(eccPrivateKey)
	//saveECCPublicKey(eccPrivateKey.PublicKey)

	// Receiver's Public Key
	receiverPublicKey := loadECCPublicKey("public_key.crt")

	// Receiver's Private Key
	receiverPrivateKey := loadECCPrivateKey("private_key.crt")

	fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))
	fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt(encryptedFile, decryptedFile, receiverPrivateKey))
}

func hybridEncryptAndUpload() string {

	// Code

	// AES 128-bit key
	aesKey := getHybridKey(password)

	// Receiver's Public Key
	receiverPublicKey := loadECCPublicKey("public_key.crt")

	fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))

	cid := uploadToIPFS(encryptedFile)
	fmt.Printf("\nCID : %s\n", cid)

	return cid
}

func hybridDownloadAndDecrypt(inputFile string, cid string) {

	// Code

	downloadFromIPFS(inputFile, cid)

	// Receiver's Private Key
	receiverPrivateKey := loadECCPrivateKey("private_key.crt")

	fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt(inputFile, decryptedFile, receiverPrivateKey))
}

func runAESECDH() {

	// Code

	//!Generate and Save Key
	// senderPrivateKey := generateECDHKeyPair()

	// saveECDHPrivateKey(senderPrivateKey, "private_key_sender")
	// saveECDHPublicKey(&senderPrivateKey.PublicKey, "public_key_sender")

	// receiverPrivateKey := generateECDHKeyPair()

	// saveECDHPrivateKey(receiverPrivateKey, "private_key_receiver")
	// saveECDHPublicKey(&receiverPrivateKey.PublicKey, "public_key_receiver")

	// Load Key
	senderPrivateKey := loadECDHPrivateKey("private_key_sender.key")
	senderPublicKey := loadECDHPublicKey("public_key_sender.key")

	receiverPrivateKey := loadECDHPrivateKey("private_key_receiver.key")
	receiverPublicKey := loadECDHPublicKey("public_key_receiver.key")

	// Derive Shared Secret
	senderSecret := deriveSharedSecret(senderPrivateKey, receiverPublicKey)
	receiverSecret := deriveSharedSecret(receiverPrivateKey, senderPublicKey)

	//! Validate Shared Secret
	// if !validateSecret(senderSecret, receiverSecret) {
	// 	fmt.Errorf("Error : Incorrect Shared Secret !!!")
	// }

	// Encrypt and Decrypt
	fmt.Printf("\nTime to Encrypt using AES and ECDH : %s\n", AesEcdhEncrypt(inputFile, encryptedFile, senderSecret))
	fmt.Printf("\nTime to Decrypt using AES and ECDH: %s\n", AesEcdhDecrypt(encryptedFile, decryptedFile, receiverSecret))
}

func main() {

	//// Init ECC
	//eccPrivateKey := generateECCKeyPair()
	//
	//savePrivateKey(eccPrivateKey)
	//savePublicKey(eccPrivateKey.PublicKey)

	// runAES()

	// runHybridAESECC()

	// cid := hybridEncryptAndUpload()

	// hybridDownloadAndDecrypt("Encrypted-Novel-File-IPFS.txt.enc", cid)

	runAESECDH()
}
