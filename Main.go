package main

import "fmt"

var APP_MODE = AES_ECDH

// Key Files
var ECC_PrivateKey_Receiver = "ECC_PRV_KEY_SENDER.key"
var ECC_PublicKey_Receiver = "ECC_PUB_KEY_SENDER.key"

var ECDH_PrivateKey_Sender = "ECDH_PRV_KEY_SENDER.key"
var ECDH_PublicKey_Sender = "ECDH_PUB_KEY_SENDER.key"
var ECDH_PrivateKey_Receiver = "ECDH_PRV_KEY_RECEIVER.key"
var ECDH_PublicKey_Receiver = "ECDH_PUB_KEY_RECEIVER.key"

var password = "12345678"
var inputFile = "Input.txt"
var encryptedFile = "Input.txt.enc"
var decryptedFile = "Input-Decrypted.txt"
var downloadedFile = "Input-IPFS-Download.txt"

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

	if !checkKeyFile(ECC_PublicKey_Receiver) && !checkKeyFile(ECC_PrivateKey_Receiver) {

		//* Generate and Save Key
		eccPrivateKey := generateECCKeyPair()

		saveECCPrivateKey(eccPrivateKey, ECC_PrivateKey_Receiver)
		saveECCPublicKey(eccPrivateKey.PublicKey, ECC_PublicKey_Receiver)
	}

	// Receiver's Public Key
	receiverPublicKey := loadECCPublicKey(ECC_PublicKey_Receiver)

	// Receiver's Private Key
	receiverPrivateKey := loadECCPrivateKey(ECC_PrivateKey_Receiver)

	fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))
	fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt(encryptedFile, decryptedFile, receiverPrivateKey))
}

func runAESECDH() {

	// Code
	if !checkKeyFile(ECDH_PublicKey_Sender) &&
		!checkKeyFile(ECDH_PrivateKey_Sender) &&
		!checkKeyFile(ECDH_PublicKey_Receiver) &&
		!checkKeyFile(ECDH_PrivateKey_Receiver) {

		//* Generate and Save Key
		senderPrivateKey := generateECDHKeyPair()

		saveECDHPrivateKey(senderPrivateKey, ECDH_PrivateKey_Sender)
		saveECDHPublicKey(&senderPrivateKey.PublicKey, ECDH_PublicKey_Sender)

		receiverPrivateKey := generateECDHKeyPair()

		saveECDHPrivateKey(receiverPrivateKey, ECDH_PrivateKey_Receiver)
		saveECDHPublicKey(&receiverPrivateKey.PublicKey, ECDH_PublicKey_Receiver)
	}

	//* Load Key
	senderPrivateKey := loadECDHPrivateKey(ECDH_PrivateKey_Sender)
	senderPublicKey := loadECDHPublicKey(ECDH_PublicKey_Sender)

	receiverPrivateKey := loadECDHPrivateKey(ECDH_PrivateKey_Receiver)
	receiverPublicKey := loadECDHPublicKey(ECDH_PublicKey_Receiver)

	//* Derive Shared Secret
	senderSecret := deriveSharedSecret(senderPrivateKey, receiverPublicKey)
	receiverSecret := deriveSharedSecret(receiverPrivateKey, senderPublicKey)

	// Encrypt and Decrypt
	fmt.Printf("\nTime to Encrypt using AES and ECDH : %s\n", AesEcdhEncrypt(inputFile, encryptedFile, senderSecret))
	fmt.Printf("\nTime to Decrypt using AES and ECDH: %s\n", AesEcdhDecrypt(encryptedFile, decryptedFile, receiverSecret))
}

func hybridEncryptAndUpload(appMode int) string {

	// Code
	if appMode == AES_ECC {

		if !checkKeyFile(ECC_PublicKey_Receiver) && !checkKeyFile(ECC_PrivateKey_Receiver) {

			//* Generate and Save Key
			eccPrivateKey := generateECCKeyPair()

			saveECCPrivateKey(eccPrivateKey, ECC_PrivateKey_Receiver)
			saveECCPublicKey(eccPrivateKey.PublicKey, ECC_PublicKey_Receiver)
		}

		// AES 128-bit key
		aesKey := getHybridKey(password)

		// Receiver's Public Key
		receiverPublicKey := loadECCPublicKey("public_key.key")

		fmt.Printf("\nTime to Encrypt using AES and ECC : %s\n", AesEccEncrypt(inputFile, encryptedFile, aesKey, receiverPublicKey))

	} else if appMode == AES_ECDH {

		if !checkKeyFile(ECDH_PublicKey_Sender) &&
			!checkKeyFile(ECDH_PrivateKey_Sender) &&
			!checkKeyFile(ECDH_PublicKey_Receiver) &&
			!checkKeyFile(ECDH_PrivateKey_Receiver) {

			//* Generate and Save Key
			senderPrivateKey := generateECDHKeyPair()

			saveECDHPrivateKey(senderPrivateKey, ECDH_PrivateKey_Sender)
			saveECDHPublicKey(&senderPrivateKey.PublicKey, ECDH_PublicKey_Sender)

			receiverPrivateKey := generateECDHKeyPair()

			saveECDHPrivateKey(receiverPrivateKey, ECDH_PrivateKey_Receiver)
			saveECDHPublicKey(&receiverPrivateKey.PublicKey, ECDH_PublicKey_Receiver)
		}

		//* Load Keys
		senderPrivateKey := loadECDHPrivateKey(ECDH_PrivateKey_Sender)
		receiverPublicKey := loadECDHPublicKey(ECDH_PublicKey_Receiver)

		//* Derive Shared Secret
		senderSecret := deriveSharedSecret(senderPrivateKey, receiverPublicKey)

		//* Encrypt File
		fmt.Printf("\nTime to Encrypt using AES and ECDH : %s\n", AesEcdhEncrypt(inputFile, encryptedFile, senderSecret))
	}

	cid := uploadToIPFS(encryptedFile)
	fmt.Printf("\nCID : %s\n", cid)

	return cid
}

func hybridDownloadAndDecrypt(inputFile string, cid string, appMode int) {

	// Code
	downloadFromIPFS(inputFile, cid)

	if appMode == AES_ECC {

		// Receiver's Private Key
		receiverPrivateKey := loadECCPrivateKey("private_key.key")

		fmt.Printf("\nTime to Decrypt using AES and ECC: %s\n", AesEccDecrypt(inputFile, decryptedFile, receiverPrivateKey))

	} else if appMode == AES_ECDH {

		//* Load Keys
		senderPublicKey := loadECDHPublicKey(ECDH_PublicKey_Sender)
		receiverPrivateKey := loadECDHPrivateKey(ECDH_PrivateKey_Receiver)

		//* Derive Shared Secret
		receiverSecret := deriveSharedSecret(receiverPrivateKey, senderPublicKey)

		//* Decrypt
		fmt.Printf("\nTime to Decrypt using AES and ECDH: %s\n", AesEcdhDecrypt(encryptedFile, decryptedFile, receiverSecret))
	}
}

func main() {

	// runAES()

	// runHybridAESECC()

	// runAESECDH()

	fmt.Println("\n----------------------------------------------------------------------------")
	fmt.Println("ENCRYPT AND UPLOAD")
	fmt.Println("----------------------------------------------------------------------------")
	cid := hybridEncryptAndUpload(APP_MODE)
	fmt.Println("\n----------------------------------------------------------------------------")

	fmt.Println("\n----------------------------------------------------------------------------")
	fmt.Println("DOWNLOAD AND DECRYPT")
	fmt.Println("----------------------------------------------------------------------------")
	hybridDownloadAndDecrypt(downloadedFile, cid, APP_MODE)
	fmt.Println("\n----------------------------------------------------------------------------")

}
