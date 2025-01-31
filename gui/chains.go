package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

const caConfFile = "/opt/boulder/labca/config/ca.json"
const wfeConfFile = "/opt/boulder/labca/config/wfe2.json"

// From boulder: cmd/boulder-wfe2/main.go
type WFEConfig struct {
	WFE struct {
		Chains [][]string `validate:"required,min=1,dive,min=2,dive,required"`
	}
}

// From boulder: issuance/issuer.go
type IssuerLoc struct {
	ConfigFile  string `validate:"required_without_all=PKCS11 File" json:"configFile"`
	CertFile    string `validate:"required" json:"certFile,omitempty"`
	NumSessions int    `json:"numSessions"`
}

// From boulder: issuance/issuer.go
type IssuerConfig struct {
	Active bool `json:"active"`

	IssuerURL string `validate:"required,url" json:"issuerURL,omitempty"`
	OCSPURL   string `validate:"required,url" json:"ocspURL,omitempty"`
	CRLURL    string `validate:"omitempty,url" json:"crlURL,omitempty"`

	Location IssuerLoc `json:"location,omitempty"`
}

// From boulder: cmd/boulder-ca/main.go but deconstructed
type Issuance struct {
	Issuers []IssuerConfig `validate:"min=1,dive" json:"issuers"`
}
type CA struct {
	Issuance Issuance `json:"issuance"`
}
type CAConfig struct {
	CA CA `json:"ca"`
}

// CertDetails contains info about each certificate for use in the GUI
type CertDetails struct {
	CertFile     string
	BaseName     string
	Subject      string
	KeyType      string
	IsRoot       bool
	ActiveIssuer bool
	NotAfter     string
	Details      string
}

type CertChain struct {
	RootCert    CertDetails
	IssuerCerts []CertDetails
}

func getCertFileKeyType(certFile string) (string, error) {
	crt, err := readCertificate(certFile)
	if err != nil {
		fmt.Println("cannot read certificate file '" + certFile + "': " + fmt.Sprint(err))
		return "", err
	}

	if crt.PublicKeyAlgorithm == x509.RSA {
		return "RSA", nil
	} else if crt.PublicKeyAlgorithm == x509.ECDSA {
		return "ECDSA", nil
	} else {
		return "", fmt.Errorf("unknown public key algorithm: %s", crt.PublicKeyAlgorithm)
	}
}

func getCertFileDetails(certFile string) (string, error) {
	var details string

	res, err := exeCmd("openssl x509 -noout -text -nameopt utf8 -in " + certFile)
	if err != nil {
		fmt.Println("cannot get details from '" + certFile + "': " + fmt.Sprint(err))
		return "", err
	}
	details = string(res)

	return details, nil
}

func getCertFileNotAFter(certFile string) (string, error) {
	var notafter string

	res, err := exeCmd("openssl x509 -noout -enddate -nameopt utf8 -in " + certFile)
	if err != nil {
		fmt.Println("cannot get enddate from '" + certFile + "': " + fmt.Sprint(err))
		return "", err
	}
	if len(res) <= 9 {
		fmt.Println("enddate of '" + certFile + "'does not start with 'notAfter='")
		return "", errors.New("enddate of '" + certFile + "'does not start with 'notAfter='")
	}
	notafter = string(res[9 : len(res)-1])
	return notafter, nil
}

func getCertFileSubject(certFile string) (string, error) {
	var subject string

	res, err := exeCmd("openssl x509 -noout -subject -nameopt utf8 -in " + certFile)
	if err != nil {
		fmt.Println("cannot get subject from '" + certFile + "': " + fmt.Sprint(err))
		return "", err
	}
	if len(res) <= 8 {
		fmt.Println("subject of '" + certFile + "'does not start with 'subject='")
		return "", errors.New("subject of '" + certFile + "'does not start with 'subject='")
	}
	subject = string(res[8 : len(res)-1])
	return subject, nil
}

func getRawCAChains() []IssuerConfig {
	caConf, err := os.Open(caConfFile)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer caConf.Close()

	byteValue, _ := io.ReadAll(caConf)

	var result CAConfig
	json.Unmarshal([]byte(byteValue), &result)

	return result.CA.Issuance.Issuers
}

func enhanceChains(chains []CertChain) []CertChain {
	rawChains := getRawCAChains()

	for i := 0; i < len(rawChains); i++ {
		for k := 0; k < len(chains); k++ {
			for n := 0; n < len(chains[k].IssuerCerts); n++ {
				if chains[k].IssuerCerts[n].CertFile == rawChains[i].Location.CertFile {
					chains[k].IssuerCerts[n].ActiveIssuer = rawChains[i].Active
					certFile := locateFile(rawChains[i].Location.CertFile)
					if kt, err := getCertFileKeyType(certFile); err == nil {
						chains[k].IssuerCerts[n].KeyType = kt
					}
					if d, err := getCertFileDetails(certFile); err == nil {
						chains[k].IssuerCerts[n].Details = d
					}
					if na, err := getCertFileNotAFter(certFile); err == nil {
						chains[k].IssuerCerts[n].NotAfter = na
					}
					if s, err := getCertFileSubject(certFile); err == nil {
						chains[k].IssuerCerts[n].Subject = s
					}
				}
			}

			if chains[k].RootCert.Subject == "" {
				certFile := locateFile(chains[k].RootCert.CertFile)
				if kt, err := getCertFileKeyType(certFile); err == nil {
					chains[k].RootCert.KeyType = kt
				}
				if d, err := getCertFileDetails(certFile); err == nil {
					chains[k].RootCert.Details = d
				}
				if na, err := getCertFileNotAFter(certFile); err == nil {
					chains[k].RootCert.NotAfter = na
				}
				if s, err := getCertFileSubject(certFile); err == nil {
					chains[k].RootCert.Subject = s
				}
			}
		}
	}

	return chains
}

func getRawWFEChains() [][]string {
	wfeConf, err := os.Open(wfeConfFile)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer wfeConf.Close()

	byteValue, _ := io.ReadAll(wfeConf)

	var result WFEConfig
	json.Unmarshal([]byte(byteValue), &result)

	return result.WFE.Chains
}

func getChains() []CertChain {
	var chains []CertChain

	rawChains := getRawWFEChains()

	for i := 0; i < len(rawChains); i++ {
		chain := rawChains[i]
		issuer := chain[0]
		root := chain[1]

		var certChain CertChain
		cIdx := -1
		for k := 0; k < len(chains); k++ {
			if chains[k].RootCert.CertFile == root {
				certChain = chains[k]
				cIdx = k
			}
		}

		if cIdx < 0 {
			base := filepath.Base(root)
			base = strings.TrimSuffix(base, filepath.Ext(base))
			certChain = CertChain{RootCert: CertDetails{
				CertFile: root,
				BaseName: base,
				IsRoot:   true,
			}}
			chains = append(chains, certChain)
			cIdx = len(chains) - 1
		}

		base := filepath.Base(issuer)
		base = strings.TrimSuffix(base, filepath.Ext(base))
		certChain.IssuerCerts = append(certChain.IssuerCerts, CertDetails{
			CertFile: issuer,
			BaseName: base,
			IsRoot:   false,
		})

		chains[cIdx] = certChain
	}

	chains = enhanceChains(chains)

	return chains
}

func setUseForLeavesFile(filename, active string) error {
	caConf, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return errors.New("could not open config file: " + err.Error())
	}
	defer caConf.Close()

	byteValue, _ := io.ReadAll(caConf)

	var result CAConfig
	if err = json.Unmarshal([]byte(byteValue), &result); err != nil {
		return errors.New("could not parse config file: " + err.Error())
	}

	// Make sure that the named certificate(s) exist
	foundActive := false
	for i := 0; i < len(result.CA.Issuance.Issuers); i++ {
		if strings.Contains(result.CA.Issuance.Issuers[i].Location.CertFile, active) {
			foundActive = true
		}
	}
	if !foundActive {
		return errors.New("certificate '" + active + "' not found in ca file")
	}

	// Now set the flags for the named certificate(s)
	for i := 0; i < len(result.CA.Issuance.Issuers); i++ {
		if active != "" {
			result.CA.Issuance.Issuers[i].Active = strings.Contains(result.CA.Issuance.Issuers[i].Location.CertFile, active)
		}
	}

	// Write the modified data back to file, using regex magic to replace only the issuers list...
	if jsonString, err := json.MarshalIndent(result, "", "\t"); err == nil {
		re := regexp.MustCompile(`(?s).*"issuers": \[(.*?)\s*\].*`)
		iss := re.ReplaceAll(jsonString, []byte("$1"))

		read, err := os.ReadFile(filename)
		if err != nil {
			fmt.Println(err)
			return errors.New("could not read config file: " + err.Error())
		}
		re = regexp.MustCompile(`(?s)(\s*"issuers": \[).*?(\s*\])`)
		res := re.ReplaceAll(read, []byte("$1"+string(iss)+"$2"))

		if err = os.WriteFile(filename, res, 0640); err != nil {
			fmt.Println(err)
			return errors.New("could not write config file: " + err.Error())
		}
	} else {
		return errors.New("could not convert json data: " + err.Error())
	}

	return nil
}

func setUseForLeaves(active string) error {
	if err := exec.Command("cp", "-f", caConfFile, caConfFile+"_BAK").Run(); err != nil {
		return errors.New("could not create ca backup file: " + err.Error())
	}

	if err := setUseForLeavesFile(caConfFile, active); err != nil {
		exec.Command("mv", caConfFile+"_BAK", caConfFile).Run()
		return err
	}

	exec.Command("rm", caConfFile+"_BAK").Run()

	if active != "" {
		viper.Set("certs.activeIssuer", active)
	}
	if active != "" {
		viper.WriteConfig()
	}

	return nil
}
