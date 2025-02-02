//go:build arm64

package main

import "crypto"

const CERT_FILES_PATH = "/opt/boulder/labca/certs/webpki/"

type HSMConfig struct {
	Module  string
	UserPIN string
	SOPIN   string
	SlotID  string
	Label   string
}

func (cfg *HSMConfig) Initialize(ca_type string, seqnr string) {
}

func (cfg *HSMConfig) CreateSlot() error {
	return nil
}

func (cfg *HSMConfig) GetPrivateKey() ([]byte, error) {
	return nil, nil
}

func (cfg *HSMConfig) ClearAll() error {
	return nil
}

func (cfg *HSMConfig) ImportKeyCert(keyFile, certFile string) (crypto.PublicKey, error) {
	return nil, nil
}
