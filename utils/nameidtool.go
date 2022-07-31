package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

func issuerNameID(certfile string) (int64, error) {
	cf, err := ioutil.ReadFile(certfile)
	if err != nil {
		fmt.Printf("issuerNameID: could not read cert file: %v", err)
		return 0, err
	}

	cpb, _ := pem.Decode(cf)
	crt, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		fmt.Printf("issuerNameID: could not parse x509 file: %v", err)
		return 0, err
	}

	// From issuance/issuance.go : func truncatedHash
	h := crypto.SHA1.New()
	h.Write(crt.RawSubject)
	s := h.Sum(nil)
	return int64(big.NewInt(0).SetBytes(s[:7]).Int64()), nil
}

func main() {
	if len(os.Args[1:]) < 1 {
		fmt.Printf("Usage:\n  %s <certificate.pem>\n", os.Args[0])
		os.Exit(1)
	}
	nameID, err := issuerNameID(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(nameID)
}
