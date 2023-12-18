package main

import (
	"fmt"
	eciesgo "github.com/ecies/go"
	"os"
)

// Generate ECC Key Pair
func generateECCKeyPair() *eciesgo.PrivateKey {
	// Code
	privateKey, err := eciesgo.GenerateKey()
	if err != nil {
		fmt.Printf("\nError : Failed To Generate ECC Key Pairs !!!\n")
		return nil
	}
	return privateKey
}

// Save ECC Private Key
func savePrivateKey(privateKey *eciesgo.PrivateKey) {

	// Code

	// Write Key to File
	privateKeyFile, err := os.Create("private_key.crt")
	if err != nil {
		fmt.Printf("Error Occurred While Creating File To Save Public Key : %s\n", err)
	}
	defer func(publicKeyFile *os.File) {
		err := publicKeyFile.Close()
		if err != nil {

		}
	}(privateKeyFile)

	err = os.WriteFile(privateKeyFile.Name(), privateKey.Bytes(), 0666)
	if err != nil {
		fmt.Printf("Error Occurred While Writing ECC Private Key : %s\n", err)
	}

	fmt.Println("Private Key Saved ...")
}

// Save ECC Public Key
func savePublicKey(publicKey *eciesgo.PublicKey) {
	// Code

	// Write Key to File
	publicKeyFile, err := os.Create("public_key.crt")
	if err != nil {
		fmt.Printf("Error Occurred While Creating File To Save Public Key : %s\n", err)
	}
	defer func(publicKeyFile *os.File) {
		err := publicKeyFile.Close()
		if err != nil {

		}
	}(publicKeyFile)

	err = os.WriteFile(publicKeyFile.Name(), publicKey.Bytes(false), 0666)
	if err != nil {
		fmt.Printf("Error Occurred While Writing ECC Public Key : %s\n", err)
	}

	fmt.Println("Public Key Saved ...")
}

// Load ECC Public Key
func loadPublicKey(publicKeyFile string) *eciesgo.PublicKey {
	// Code

	// Read the public key file
	fileKey, err := os.ReadFile(publicKeyFile)
	if err != nil {
		fmt.Printf("Error Occurred While Reading ECC Public Key : %s\n", err)
	}

	publicKey, _ := eciesgo.NewPublicKeyFromBytes(fileKey)

	return publicKey
}

// Load ECC Private Key
func loadPrivateKey(privateKeyFile string) *eciesgo.PrivateKey {
	// Code

	// Read the public key file
	fileKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		fmt.Printf("Error Occurred While Reading ECC Public Key : %s\n", err)
	}

	privateKey := eciesgo.NewPrivateKeyFromBytes(fileKey)

	return privateKey
}
