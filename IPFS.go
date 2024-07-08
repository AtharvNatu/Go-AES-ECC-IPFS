package main

import (
	"fmt"
	"os"

	ipfsShell "github.com/ipfs/go-ipfs-api"
)

// Uploading File to IPFS
func uploadToIPFS(inputFileName string) string {

	// Code

	// Connect to localhost IPFS Node
	ipfs := ipfsShell.NewShell("localhost:5001")

	// Open the file to upload
	inputFile, err := os.Open(inputFileName)
	if err != nil {
		fmt.Printf("uploadToIPFS() : Error Occurred While Opening Input File : %s\n", err)
	}
	defer func(inputFile *os.File) {
		err := inputFile.Close()
		if err != nil {

		}
	}(inputFile)

	// Upload the file to IPFS
	cid, err := ipfs.Add(inputFile)
	if err != nil {
		fmt.Printf("Error Occurred While Uploading Input File To IPFS : %s\n", err)
	}

	fmt.Println("\nFile Uploaded To IPFS Successfully ...")

	return cid
}

// Downloading File from IPFS
func downloadFromIPFS(outputPath string, cid string) {

	// Code

	// Connect to localhost IPFS Node
	ipfs := ipfsShell.NewShell("localhost:5001")

	// Create file at output path to save downloaded content
	outputFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("downloadFromIPFS() : Error Occurred While Creating Output File : %s\n", err)
	}
	outputFile.Close()

	// Download the file from IPFS
	err = ipfs.Get(cid, outputFile.Name())
	if err != nil {
		fmt.Printf("downloadFromIPFS() : Error Occurred While Downloading File From IPFS : %s\n", err)
	}

	fmt.Println("\nFile Downloaded From IPFS Successfully ...")
}
