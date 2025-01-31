package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math"
	"mime/multipart"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// CertificateInfo contains all data related to a certificate (file)
type CertificateInfo struct {
	IsRoot          bool
	IsFirst         bool
	KeyTypes        map[string]string
	KeyType         string
	CreateType      string
	IsRootGenerated bool
	RootSubject     string
	RootEnddate     string
	NumDays         int

	Country      string
	Organization string
	CommonName   string

	ImportFile    multipart.File
	ImportHandler *multipart.FileHeader
	ImportPwd     string

	Key         string
	Passphrase  string
	Certificate string
	CRL         string

	/*
		KeyFromHSM     bool
		HSMInfo        HSMInfo
		HSMKeys        map[string]string
		HSMKey         string
		HSMLabel       string
		StoreCertOnHSM bool
	*/

	RequestBase string
	Errors      map[string]string
}

// Initialize the CertificateInfo and set the list of available key types
func (ci *CertificateInfo) Initialize() {
	ci.Errors = make(map[string]string)

	ci.KeyTypes = make(map[string]string)
	ci.KeyTypes["rsa4096"] = "RSA-4096"
	ci.KeyTypes["rsa2048"] = "RSA-2048"
	ci.KeyTypes["ecdsa384"] = "ECDSA-384"
	ci.KeyTypes["ecdsa256"] = "ECDSA-256"

	ci.KeyType = "rsa4096"

	// ci.HSMKeys = make(map[string]string)
	// ci.StoreCertOnHSM = true
}

// ValidateGenerate that the CertificateInfo contains valid and all required data for generating a cert
func (ci *CertificateInfo) ValidateGenerate() {
	if strings.TrimSpace(ci.KeyType) == "" || strings.TrimSpace(ci.KeyTypes[ci.KeyType]) == "" {
		ci.Errors["KeyType"] = "Please select a key type/size"
	}
	if strings.TrimSpace(ci.Country) == "" || len(ci.Country) < 2 {
		ci.Errors["Country"] = "Please enter a valid 2-character country code"
	}
	if strings.TrimSpace(ci.Organization) == "" {
		ci.Errors["Organization"] = "Please enter an organization name"
	}
	if strings.TrimSpace(ci.CommonName) == "" {
		ci.Errors["CommonName"] = "Please enter a common name"
	}
}

// Validate that the CertificateInfo contains valid and all required data
func (ci *CertificateInfo) Validate() bool {
	ci.Errors = make(map[string]string)

	if ci.CreateType == "generate" {
		ci.ValidateGenerate()
	}

	if (ci.CreateType == "import") && (ci.ImportHandler != nil) {
		ext := ci.ImportHandler.Filename[len(ci.ImportHandler.Filename)-4:]
		if (ci.ImportHandler.Size == 0) || (ext != ".zip" && ext != ".pfx") {
			ci.Errors["Import"] = "Please provide a bundle (.pfx or .zip) with a key and certificate"
		}
	}

	if ci.CreateType == "upload" {
		if strings.TrimSpace(ci.Key) == "" {
			ci.Errors["Key"] = "Please provide a PEM-encoded key"
		}
		if strings.TrimSpace(ci.Certificate) == "" {
			ci.Errors["Certificate"] = "Please provide a PEM-encoded certificate"
		}
	}

	return len(ci.Errors) == 0
}

func reportError(param interface{}) error {
	lines := strings.Split(string(debug.Stack()), "\n")
	if len(lines) >= 5 {
		lines = append(lines[:0], lines[5:]...)
	}

	stop := len(lines)
	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], ".ServeHTTP(") {
			stop = i
			break
		}
	}
	lines = lines[:stop]
	lines = append(lines, "...")

	fmt.Println(strings.Join(lines, "\n"))

	res := errors.New("error: see LabCA logs for details")
	switch v := param.(type) {
	case error:
		res = errors.New("Error (" + v.Error() + ")! See LabCA logs for details")
	case []byte:
		res = errors.New("Error (" + string(v) + ")! See LabCA logs for details")
	default:
		fmt.Printf("unexpected type %T", v)
	}

	return res
}

func ceremonyConfig(path string, rewrites map[string]string) (string, error) {
	tmplBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(os.TempDir(), "ceremony-config")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	tmpl, err := template.New("config").Parse(string(tmplBytes))
	if err != nil {
		return "", err
	}
	err = tmpl.Execute(tmp, rewrites)
	if err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

func (ci *CertificateInfo) CeremonyRoot(seqnr string, use_existing_key bool) (string, error) {
	keytype := "rsa"
	keyparam := strings.Replace(ci.KeyType, "rsa", "", -1)
	algo := "SHA256WithRSA"
	if strings.HasPrefix(ci.KeyType, "ecdsa") {
		keytype = "ecdsa"
		len := strings.Replace(ci.KeyType, "ecdsa", "", -1)
		keyparam = "P-" + len
		algo = "ECDSAWithSHA" + len
	}

	notbefore := time.Now().Add(-1 * time.Second)
	notafter := notbefore.AddDate(0, 0, ci.NumDays).Add(-1 * time.Second)

	cfg := &HSMConfig{}
	cfg.Initialize("root", seqnr)
	if err := cfg.CreateSlot(); err != nil {
		return "", fmt.Errorf("failed to create root slot: %s", err.Error())
	}

	certFileName := fmt.Sprintf("%sroot-%s-cert.pem", CERT_FILES_PATH, seqnr)
	cb := renameBackup(certFileName)
	var pb BackupResult
	if !use_existing_key {
		pb = renameBackup(fmt.Sprintf("%sroot-%s-pubkey.pem", CERT_FILES_PATH, seqnr))
	}

	ceremonyCfg, err := ceremonyConfig("templates/cert-ceremonies/root.yaml", map[string]string{
		"Module":        cfg.Module,
		"UserPIN":       cfg.UserPIN,
		"SlotID":        cfg.SlotID,
		"Label":         cfg.Label,
		"Path":          CERT_FILES_PATH,
		"KeyType":       keytype,
		"KeyParam":      keyparam,
		"Extractable":   strconv.FormatBool(true), // For now, with SoftHSM, this is fine. In future we need to ask for informed consent!
		"SeqNr":         seqnr,
		"SignAlgorithm": algo,
		"CommonName":    ci.CommonName,
		"OrgName":       ci.Organization,
		"Country":       ci.Country,
		"NotBefore":     notbefore.UTC().Format("2006-01-02 15:04:05"),
		"NotAfter":      notafter.UTC().Format("2006-01-02 15:04:05"),
		"Renewal":       strconv.FormatBool(use_existing_key),
	})
	if err != nil {
		ci.Errors["Generate"] = "error preparing for root ceremony, see logs for details"
		cb.Restore()
		if !use_existing_key {
			pb.Restore()
		}
		return "", fmt.Errorf("could not fill root ceremony template: %s", err.Error())
	}
	defer os.Remove(ceremonyCfg)

	if _, err = exeCmd("/opt/boulder/bin/ceremony -config " + ceremonyCfg); err != nil {
		ci.Errors["Generate"] = "failed to execute root ceremony, see logs for details"
		cb.Restore()
		if !use_existing_key {
			pb.Restore()
		}
		return "", err
	}

	cb.Remove()
	if !use_existing_key {
		pb.Remove()
	}
	return certFileName, nil
}

func (ci *CertificateInfo) CeremonyIssuer(seqnr, rootseqnr string, use_existing_key bool) (string, error) {
	fqdn := viper.GetString("labca.fqdn")

	keytype := "rsa"
	keyparam := strings.Replace(ci.KeyType, "rsa", "", -1)
	algo := "SHA256WithRSA"
	if strings.HasPrefix(ci.KeyType, "ecdsa") {
		keytype = "ecdsa"
		len := strings.Replace(ci.KeyType, "ecdsa", "", -1)
		keyparam = "P-" + len
		algo = "ECDSAWithSHA" + len
	}

	notbefore := time.Now().Add(-1 * time.Second)
	notafter := notbefore.AddDate(0, 0, ci.NumDays).Add(-1 * time.Second)

	cfg := &HSMConfig{}
	cfg.Initialize("issuer", seqnr)
	if err := cfg.CreateSlot(); err != nil {
		return "", fmt.Errorf("failed to create issuer slot: %s", err.Error())
	}

	if !use_existing_key {
		pb := renameBackup(fmt.Sprintf("%sissuer-%s-pubkey.pem", CERT_FILES_PATH, seqnr))
		jb := renameBackup(fmt.Sprintf("%sissuer-%s.pkcs11.json", CERT_FILES_PATH, seqnr))

		keyCfg, err := ceremonyConfig("templates/cert-ceremonies/issuer-key.yaml", map[string]string{
			"Module":      cfg.Module,
			"UserPIN":     cfg.UserPIN,
			"SlotID":      cfg.SlotID,
			"Label":       cfg.Label,
			"Path":        CERT_FILES_PATH,
			"KeyType":     keytype,
			"KeyParam":    keyparam,
			"Extractable": strconv.FormatBool(true), // For now, with SoftHSM, this is fine. In future we need to ask for informed consent!
			"SeqNr":       seqnr,
		})
		if err != nil {
			ci.Errors["Generate"] = "error preparing for issuer key ceremony, see logs for details"
			pb.Restore()
			jb.Restore()
			return "", fmt.Errorf("could not fill issuer key ceremony template: %s", err.Error())
		}
		defer os.Remove(keyCfg)

		if _, err = exeCmd("/opt/boulder/bin/ceremony -config " + keyCfg); err != nil {
			ci.Errors["Generate"] = "failed to execute issuer key ceremony, see logs for details"
			pb.Restore()
			jb.Restore()
			return "", err
		}

		pb.Remove()
		jb.Remove()
	}

	cfg = &HSMConfig{}
	cfg.Initialize("root", rootseqnr)
	if err := cfg.CreateSlot(); err != nil {
		return "", fmt.Errorf("failed to get root slot: %s", err.Error())
	}

	certFileName := fmt.Sprintf("%sissuer-%s-cert.pem", CERT_FILES_PATH, seqnr)
	cb := renameBackup(certFileName)

	ceremonyCfg, err := ceremonyConfig("templates/cert-ceremonies/issuer-cert.yaml", map[string]string{
		"Module":        cfg.Module,
		"UserPIN":       cfg.UserPIN,
		"RootSlotID":    cfg.SlotID,
		"RootLabel":     cfg.Label,
		"Path":          CERT_FILES_PATH,
		"SeqNr":         seqnr,
		"RootSeqNr":     rootseqnr,
		"SignAlgorithm": algo,
		"CommonName":    ci.CommonName,
		"OrgName":       ci.Organization,
		"Country":       ci.Country,
		"NotBefore":     notbefore.UTC().Format("2006-01-02 15:04:05"),
		"NotAfter":      notafter.UTC().Format("2006-01-02 15:04:05"),
		"CrlUrl":        fmt.Sprintf("http://%s/crl", fqdn),
		"IssuerUrl":     fmt.Sprintf("http://%s/aia/issuer", fqdn), // TODO: fix this
	})
	if err != nil {
		ci.Errors["Generate"] = "error preparing for issuer cert ceremony, see logs for details"
		cb.Restore()
		return "", fmt.Errorf("could not fill issuer cert ceremony template: %s", err.Error())
	}
	defer os.Remove(ceremonyCfg)

	if _, err = exeCmd("/opt/boulder/bin/ceremony -config " + ceremonyCfg); err != nil {
		ci.Errors["Generate"] = "failed to execute issuer cert ceremony, see logs for details"
		cb.Restore()
		return "", err
	}

	cb.Remove()
	return certFileName, nil
}

func readCertificate(filename string) (*x509.Certificate, error) {
	read, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return nil, errors.New("could not read '" + filename + "': " + err.Error())
	}
	block, _ := pem.Decode(read)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println(block)
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

func (ci *CertificateInfo) CeremonyRootCRL(seqnr string) error {
	now := time.Now()

	if viper.Get("crl_root_days") == nil || viper.Get("crl_root_days") == "" {
		viper.Set("crl_root_days", 365)
		viper.WriteConfig()
	}
	crlint, err := time.ParseDuration(fmt.Sprintf("%dh", viper.GetInt("crl_root_days")*24-1))
	if err != nil {
		crlint, _ = time.ParseDuration("8759h") // 365 days - 1 hour
	}

	cert, err := readCertificate(fmt.Sprintf("%sroot-%s-cert.pem", CERT_FILES_PATH, seqnr))
	if err != nil {
		return err
	}

	thisupdate := now
	if thisupdate.Before(cert.NotBefore) {
		thisupdate = cert.NotBefore.Add(1 * time.Second)
	}

	nextupdate := now.Add(crlint)
	maxNext := cert.NotAfter.Add(-1 * time.Second)
	if nextupdate.After(maxNext) {
		nextupdate = maxNext
	}
	if nextupdate.Sub(thisupdate) > time.Hour*24*365 {
		nextupdate = thisupdate.Add(time.Hour * 24 * 365).Add(-1 * time.Second)
	}

	crlnumber := fmt.Sprintf("%02d%03d%s", now.Year()-2000, now.YearDay(), seqnr)

	cb := renameBackup(fmt.Sprintf("%sroot-%s-crl.pem", CERT_FILES_PATH, seqnr))

	cfg := &HSMConfig{}
	cfg.Initialize("root", seqnr)
	if err := cfg.CreateSlot(); err != nil {
		return fmt.Errorf("failed to get root slot: %s", err.Error())
	}

	keyCfg, err := ceremonyConfig("templates/cert-ceremonies/root-crl.yaml", map[string]string{
		"Module":     cfg.Module,
		"UserPIN":    cfg.UserPIN,
		"RootSlotID": cfg.SlotID,
		"RootLabel":  cfg.Label,
		"Path":       CERT_FILES_PATH,
		"RootSeqNr":  seqnr,
		"ThisUpdate": thisupdate.UTC().Format("2006-01-02 15:04:05"),
		"NextUpdate": nextupdate.UTC().Format("2006-01-02 15:04:05"),
		"CrlNumber":  crlnumber,
	})
	if err != nil {
		ci.Errors["CRL"] = "error preparing for root crl ceremony, see logs for details"
		cb.Restore()
		return fmt.Errorf("could not fill root crl ceremony template: %s", err.Error())
	}
	defer os.Remove(keyCfg)

	if _, err = exeCmd("/opt/boulder/bin/ceremony -config " + keyCfg); err != nil {
		ci.Errors["CRL"] = "failed to execute root crl ceremony, see logs for details"
		cb.Restore()
		return err
	}

	cb.Remove()
	return nil
}

// Generate a key and certificate file for the data from this CertificateInfo
func (ci *CertificateInfo) Generate(certBase string) error {
	var err error
	if ci.IsRoot {
		_, err = ci.CeremonyRoot("01", false)

		viper.Set("crl_root_days", ci.NumDays)
		viper.WriteConfig()
	} else {
		_, err = ci.CeremonyIssuer("01", "01", false)
	}

	if err != nil {
		log.Printf("failed to create certificate: %s", err.Error())
		return errors.New("failed to create certificate, see logs for details")
	}

	if !ci.IsRoot {
		// Create CRLs stating that the intermediates are not revoked.
		err = ci.CeremonyRootCRL("01")

		if err != nil {
			log.Printf("failed to create crl: %s", err.Error())
			return errors.New("failed to create crl, see logs for details")
		}
	}

	return nil
}

// ImportPkcs12 imports an uploaded PKCS#12 / PFX file
func (ci *CertificateInfo) ImportPkcs12(tmpFile string, tmpKey string, tmpCert string) error {
	if ci.IsRoot {
		if (strings.Index(ci.ImportHandler.Filename, "labca-root-01-cert") != 0) && (strings.Index(ci.ImportHandler.Filename, "labca_root") != 0) {
			fmt.Printf("WARNING: importing root from .pfx file but name is %s\n", ci.ImportHandler.Filename)
		}
	} else {
		if (strings.Index(ci.ImportHandler.Filename, "labca-issuer-01-cert") != 0) && (strings.Index(ci.ImportHandler.Filename, "labca_issuer") != 0) {
			fmt.Printf("WARNING: importing issuer from .pfx file but name is %s\n", ci.ImportHandler.Filename)
		}
	}

	pwd := "pass:dummy"
	if ci.ImportPwd != "" {
		pwd = "pass:" + strings.Replace(ci.ImportPwd, " ", "\\\\", -1)
	}

	if out, err := exeCmd("openssl pkcs12 -in " + strings.Replace(tmpFile, " ", "\\\\", -1) + " -password " + pwd + " -nocerts -nodes -out " + tmpKey); err != nil {
		if strings.Contains(string(out), "invalid password") {
			return errors.New("incorrect password")
		}

		return reportError(err)
	}
	if out, err := exeCmd("openssl pkcs12 -in " + strings.Replace(tmpFile, " ", "\\\\", -1) + " -password " + pwd + " -nokeys -out " + tmpCert); err != nil {
		if strings.Contains(string(out), "invalid password") {
			return errors.New("incorrect password")
		}

		return reportError(err)
	}

	return nil
}

// ImportZip imports an uploaded ZIP file
func (ci *CertificateInfo) ImportZip(tmpFile string, tmpDir string) error {
	if ci.IsRoot {
		if (strings.Index(ci.ImportHandler.Filename, "labca-root-01-cert") != 0) && (strings.Index(ci.ImportHandler.Filename, "labca_root") != 0) && (strings.Index(ci.ImportHandler.Filename, "labca_certificates") != 0) {
			fmt.Printf("WARNING: importing root from .zip file but name is %s\n", ci.ImportHandler.Filename)
		}
	} else {
		if (strings.Index(ci.ImportHandler.Filename, "labca-issuer-01-cert") != 0) && (strings.Index(ci.ImportHandler.Filename, "labca_issuer") != 0) {
			fmt.Printf("WARNING: importing issuer from .zip file but name is %s\n", ci.ImportHandler.Filename)
		}
	}

	cmd := "unzip -j"
	if ci.ImportPwd != "" {
		cmd = cmd + " -P " + strings.Replace(ci.ImportPwd, " ", "\\\\", -1)
	} else {
		cmd = cmd + " -P dummy"
	}
	cmd = cmd + " " + strings.Replace(tmpFile, " ", "\\\\", -1) + " -d " + tmpDir

	if _, err := exeCmd(cmd); err != nil {
		if err.Error() == "exit status 82" {
			return errors.New("incorrect password")
		}

		return reportError(err)
	}

	return nil
}

// Import a certificate and key file
func (ci *CertificateInfo) Import(tmpDir string, tmpKey string, tmpCert string) error {
	tmpFile := filepath.Join(tmpDir, ci.ImportHandler.Filename)

	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	io.Copy(f, ci.ImportFile)

	contentType := ci.ImportHandler.Header.Get("Content-Type")
	if contentType == "application/x-pkcs12" {
		err := ci.ImportPkcs12(tmpFile, tmpKey, tmpCert)
		if err != nil {
			return err
		}

	} else if contentType == "application/zip" || contentType == "application/x-zip-compressed" {
		err := ci.ImportZip(tmpFile, tmpDir)
		if err != nil {
			return err
		}

	} else {
		return errors.New("Content Type '" + contentType + "' not supported!")
	}

	return nil
}

// Upload a certificate and key file
func (ci *CertificateInfo) Upload(tmpKey string, tmpCert string) error {
	if ci.Key != "" {
		if err := os.WriteFile(tmpKey, []byte(ci.Key), 0644); err != nil {
			return err
		}

		pwd := "pass:dummy"
		if ci.Passphrase != "" {
			pwd = "pass:" + strings.Replace(ci.Passphrase, " ", "\\\\", -1)
		}

		if out, err := exeCmd("openssl pkey -passin " + pwd + " -in " + tmpKey + " -out " + tmpKey + "-out"); err != nil {
			if strings.Contains(string(out), ":bad decrypt:") {
				return errors.New("incorrect password")
			}

			return reportError(err)
		}

		if _, err := exeCmd("mv " + tmpKey + "-out " + tmpKey); err != nil {
			return reportError(err)
		}
	}

	if err := os.WriteFile(tmpCert, []byte(ci.Certificate), 0644); err != nil {
		return err
	}

	if out, err := exeCmd("openssl x509 -in " + tmpCert + " -out " + tmpCert + "-out"); err != nil {
		return reportError(out)
	}

	if _, err := exeCmd("mv " + tmpCert + "-out " + tmpCert); err != nil {
		return reportError(err)
	}

	return nil
}

func parseSubjectDn(subject string) map[string]string {
	trackerResultMap := map[string]string{"C=": "", "C =": "", "O=": "", "O =": "", "CN=": "", "CN =": "", "OU=": "", "OU =": ""}

	for tracker := range trackerResultMap {
		index := strings.Index(subject, tracker)

		if index < 0 {
			continue
		}

		var res string
		// track quotes for delimited fields so we know not to split on the comma
		quoteCount := 0

		for i := index + len(tracker); i < len(subject); i++ {
			char := subject[i]

			// if ", we need to count and delimit
			if char == 34 {
				quoteCount++
				if quoteCount == 2 {
					break
				} else {
					continue
				}
			}

			// comma, lets stop here but only if we don't have quotes
			if char == 44 && quoteCount == 0 {
				break
			}

			// add this individual char
			res += string(rune(char))
		}

		trackerResultMap[strings.TrimSpace(strings.TrimSuffix(tracker, "="))] = strings.TrimSpace(strings.TrimPrefix(res, "="))
	}

	for k, v := range trackerResultMap {
		if len(v) == 0 {
			delete(trackerResultMap, k)
		}
	}

	return trackerResultMap
}

// VerifyCerts verifies the root and the issuer certificates
func (ci *CertificateInfo) VerifyCerts(path string, rootCert string, rootKey string, issuerCert string, issuerKey string) error {
	var rootSubject string
	if (rootCert != "") && (rootKey != "") {
		r, err := exeCmd("openssl x509 -noout -subject -in " + rootCert)
		if err != nil {
			return reportError(err)
		}

		rootSubject = string(r[0 : len(r)-1])
		fmt.Printf("Import root with subject '%s'\n", rootSubject)

		subjectMap := parseSubjectDn(rootSubject)
		if val, ok := subjectMap["C"]; ok {
			ci.Country = val
		}
		if val, ok := subjectMap["O"]; ok {
			ci.Organization = val
		}
		if val, ok := subjectMap["CN"]; ok {
			ci.CommonName = val
		}

		keyFileExists := true
		if _, err := os.Stat(rootKey); errors.Is(err, fs.ErrNotExist) {
			keyFileExists = false
		}
		if keyFileExists {
			_, err = exeCmd("openssl pkey -noout -in " + rootKey)
			if err != nil {
				return reportError(err)
			}

			fmt.Println("Import root key")
		}
	}

	if (issuerCert != "") && (issuerKey != "") {
		r, err := exeCmd("openssl x509 -noout -subject -in " + issuerCert)
		if err != nil {
			return reportError(err)
		}

		fmt.Printf("Import issuer with subject '%s'\n", string(r[0:len(r)-1]))

		r, err = exeCmd("openssl x509 -noout -issuer -in " + issuerCert)
		if err != nil {
			return reportError(err)
		}

		issuerIssuer := string(r[0 : len(r)-1])
		fmt.Printf("Issuer certificate issued by CA '%s'\n", issuerIssuer)

		if rootSubject == "" {
			r, err := exeCmd("openssl x509 -noout -subject -in " + CERT_FILES_PATH + "root-01-cert.pem")
			if err != nil {
				return reportError(err)
			}

			rootSubject = string(r[0 : len(r)-1])
		}

		issuerIssuer = strings.Replace(issuerIssuer, "issuer=", "", -1)
		rootSubject = strings.Replace(rootSubject, "subject=", "", -1)
		if issuerIssuer != rootSubject {
			return errors.New("issuer not issued by our Root CA")
		}

		_, err = exeCmd("openssl verify -CAfile " + CERT_FILES_PATH + "root-01-cert.pem " + issuerCert)
		if err != nil {
			return errors.New("could not verify that issuer was issued by our Root CA")
		}

		_, err = exeCmd("openssl pkey -noout -in " + issuerKey)
		if err != nil {
			return reportError(err)
		}

		fmt.Println("Import issuer key")
	}

	return nil
}

// ImportFiles moves certificate files to their final location and imports the keys into the HSM
func (ci *CertificateInfo) ImportFiles(path string, rootCert string, rootKey string, issuerCert string, issuerKey string) error {
	if rootKey != "" {
		keyFileExists := true
		if _, err := os.Stat(rootKey); errors.Is(err, fs.ErrNotExist) {
			keyFileExists = false
		}
		if keyFileExists {
			rootseqnr := "01"
			cfg := &HSMConfig{}
			cfg.Initialize("root", rootseqnr)
			if err := cfg.CreateSlot(); err != nil {
				return fmt.Errorf("failed to create root slot: %s", err.Error())
			}

			pubKey, err := cfg.ImportKeyCert(rootKey, rootCert)
			if err != nil {
				return fmt.Errorf("failed to import root key: %s", err.Error())
			}

			var pubKeyBytes []byte
			if reflect.TypeOf(pubKey).String() == "rsa.PublicKey" {
				pk := pubKey.(rsa.PublicKey)
				pubKeyBytes, err = x509.MarshalPKIXPublicKey(&pk)
			} else if reflect.TypeOf(pubKey).String() == "ecdsa.PublicKey" {
				pk := pubKey.(ecdsa.PublicKey)
				pubKeyBytes, err = x509.MarshalPKIXPublicKey(&pk)
			} else {
				return fmt.Errorf("unknown private key type: %s", reflect.TypeOf(pubKey).String())
			}
			if err != nil {
				return fmt.Errorf("failed to marshal root pubkey: %s", err.Error())
			}
			file, err := os.Create(fmt.Sprintf("%sroot-%s-pubkey.pem", CERT_FILES_PATH, rootseqnr))
			if err != nil {
				return fmt.Errorf("failed to create root pubkey file: %s", err.Error())
			}
			defer file.Close()
			if err := pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}); err != nil {
				return fmt.Errorf("failed to write root pubkey: %s", err.Error())
			}
		}
	}
	if rootCert != "" {
		if _, err := exeCmd("mv " + rootCert + " " + path); err != nil {
			return reportError(err)
		}
	}

	if issuerKey != "" {
		seqnr := "01"
		cfg := &HSMConfig{}
		cfg.Initialize("issuer", seqnr)
		if err := cfg.CreateSlot(); err != nil {
			return fmt.Errorf("failed to create issuer slot: %s", err.Error())
		}

		pubKey, err := cfg.ImportKeyCert(issuerKey, issuerCert)
		if err != nil {
			return reportError(err)
		}

		var pubKeyBytes []byte
		if reflect.TypeOf(pubKey).String() == "rsa.PublicKey" {
			pk := pubKey.(rsa.PublicKey)
			pubKeyBytes, err = x509.MarshalPKIXPublicKey(&pk)
		} else if reflect.TypeOf(pubKey).String() == "ecdsa.PublicKey" {
			pk := pubKey.(ecdsa.PublicKey)
			pubKeyBytes, err = x509.MarshalPKIXPublicKey(&pk)
		} else {
			return fmt.Errorf("unknown private key type: %s", reflect.TypeOf(pubKey).String())
		}
		if err != nil {
			return fmt.Errorf("failed to marshal issuer pubkey: %s", err.Error())
		}
		file, err := os.Create(fmt.Sprintf("%sissuer-%s-pubkey.pem", CERT_FILES_PATH, seqnr))
		if err != nil {
			return fmt.Errorf("failed to create issuer pubkey file: %s", err.Error())
		}
		defer file.Close()
		if err := pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}); err != nil {
			return fmt.Errorf("failed to write issuer pubkey: %s", err.Error())
		}
	}
	if issuerCert != "" {
		if _, err := exeCmd("mv " + issuerCert + " " + path); err != nil {
			return reportError(err)
		}
	}

	return nil
}

// Extract key and certificate files from a container file
func (ci *CertificateInfo) Extract(certBase string, tmpDir string, wasCSR bool) error {
	var rootCert string
	var rootKey string
	var issuerCert string
	var issuerKey string

	path := CERT_FILES_PATH // TODO !!

	if ci.IsRoot {
		rootCert = filepath.Join(tmpDir, "root-01-cert.pem")
		rootKey = filepath.Join(tmpDir, "root-01-key.pem")

		if _, err := os.Stat(rootCert); errors.Is(err, fs.ErrNotExist) {
			altCert := filepath.Join(tmpDir, "root-ca.pem")
			if _, err = os.Stat(altCert); err == nil {
				if _, err := exeCmd("mv " + altCert + " " + rootCert); err != nil {
					return err
				}
			}

			altKey := filepath.Join(tmpDir, "root-ca.key")
			if _, err = os.Stat(altKey); err == nil {
				if _, err := exeCmd("mv " + altKey + " " + rootKey); err != nil {
					return err
				}
			}
		}

		if _, err := os.Stat(rootCert); errors.Is(err, fs.ErrNotExist) {
			altCert := filepath.Join(tmpDir, "test-root.pem")
			if _, err = os.Stat(altCert); err == nil {
				if _, err := exeCmd("mv " + altCert + " " + rootCert); err != nil {
					return err
				}
			}

			altKey := filepath.Join(tmpDir, "test-root.key")
			if _, err = os.Stat(altKey); err == nil {
				if _, err := exeCmd("mv " + altKey + " " + rootKey); err != nil {
					return err
				}
			}

			if _, err := os.Stat(rootCert); errors.Is(err, fs.ErrNotExist) {
				return errors.New("file does not contain root certificate")
			}
		}
	}

	issuerCert = filepath.Join(tmpDir, "issuer-01-cert.pem")
	issuerKey = filepath.Join(tmpDir, "issuer-01-key.pem")

	if _, err := os.Stat(issuerCert); errors.Is(err, fs.ErrNotExist) {
		if ci.IsRoot {
			issuerCert = ""
		} else {
			altCert := filepath.Join(tmpDir, "ca-int.pem")
			if _, err = os.Stat(altCert); err == nil {
				if _, err := exeCmd("mv " + altCert + " " + issuerCert); err != nil {
					return err
				}
			}

			if _, err := os.Stat(issuerCert); errors.Is(err, fs.ErrNotExist) {
				altCert := filepath.Join(tmpDir, "test-ca.pem")
				if _, err = os.Stat(altCert); err == nil {
					if _, err := exeCmd("mv " + altCert + " " + issuerCert); err != nil {
						return err
					}
				}

				if _, err := os.Stat(issuerCert); errors.Is(err, fs.ErrNotExist) {
					return errors.New("file does not contain issuer certificate")
				}
			}
		}
	}
	if _, err := os.Stat(issuerKey); errors.Is(err, fs.ErrNotExist) {
		if ci.IsRoot || wasCSR {
			issuerKey = ""
		} else {
			altKey := filepath.Join(tmpDir, "ca-int.key")
			if _, err = os.Stat(altKey); err == nil {
				if _, err := exeCmd("mv " + altKey + " " + issuerKey); err != nil {
					return err
				}
			}

			if _, err := os.Stat(issuerKey); errors.Is(err, fs.ErrNotExist) {
				altKey := filepath.Join(tmpDir, "test-ca.key")
				if _, err = os.Stat(altKey); err == nil {
					if _, err := exeCmd("mv " + altKey + " " + issuerKey); err != nil {
						return err
					}
				}

				if _, err := os.Stat(issuerKey); errors.Is(err, fs.ErrNotExist) {
					return errors.New("file does not contain issuer key")
				}
			}
		}
	}

	err := ci.VerifyCerts(path, rootCert, rootKey, issuerCert, issuerKey)
	if err != nil {
		return err
	}

	// All is good now, move files to their permanent location...
	err = ci.ImportFiles(path, rootCert, rootKey, issuerCert, issuerKey)
	if err != nil {
		return err
	}

	// Extract enddate to determine what the default CRL validity should be
	if ci.IsRoot {
		certFile := path + filepath.Base(rootCert)
		read, err := os.ReadFile(certFile)
		if err != nil {
			fmt.Println(err)
			return errors.New("could not read '" + certFile + "': " + err.Error())
		}
		block, _ := pem.Decode(read)
		if block == nil || block.Type != "CERTIFICATE" {
			fmt.Println(block)
			return errors.New("failed to decode PEM block containing certificate")
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		numDays := time.Until(crt.NotAfter).Hours() / 24
		// TODO: adjust for max root ceremony value...
		viper.Set("crl_root_days", int(math.Ceil(numDays)))
		viper.WriteConfig()

	} else {
		// Create CRLs stating that the intermediates are not revoked.
		err = ci.CeremonyRootCRL("01")

		if err != nil {
			log.Printf("failed to create crl: %s", err.Error())
			return errors.New("failed to create crl, see logs for details")
		}
	}

	return nil
}

// Create a new pair of key + certificate files based on the info in CertificateInfo
func (ci *CertificateInfo) Create(certBase string, wasCSR bool) error {
	tmpDir, err := os.MkdirTemp("", "labca")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tmpDir)

	var tmpKey string
	var tmpCert string
	if ci.IsRoot {
		tmpKey = filepath.Join(tmpDir, "root-01-key.pem")
		tmpCert = filepath.Join(tmpDir, "root-01-cert.pem")
	} else {
		tmpKey = filepath.Join(tmpDir, "issuer-01-key.pem")
		tmpCert = filepath.Join(tmpDir, "issuer-01-cert.pem")
	}

	if ci.CreateType == "generate" {
		err := ci.Generate(certBase)
		if err != nil {
			return err
		}

	} else if ci.CreateType == "import" {
		err := ci.Import(tmpDir, tmpKey, tmpCert)
		if err != nil {
			return err
		}

	} else if ci.CreateType == "upload" {
		err := ci.Upload(tmpKey, tmpCert)
		if err != nil {
			return err
		}

	} else {
		return fmt.Errorf("unknown CreateType")
	}

	// This is shared between pfx/zip import and pem text upload
	if ci.CreateType != "generate" {
		err := ci.Extract(certBase, tmpDir, wasCSR)
		if err != nil {
			return err
		}
	}

	return nil
}

func storeRootKey(path, certName, tmpDir, keyData, passphrase string) (bool, string) {
	tmpKey := filepath.Join(tmpDir, certName+".key")

	if err := os.WriteFile(tmpKey, []byte(keyData), 0600); err != nil {
		return false, err.Error()
	}

	if passphrase != "" {
		pwd := "pass:" + strings.Replace(passphrase, " ", "\\\\", -1)

		if out, err := exeCmd("openssl pkey -passin " + pwd + " -in " + tmpKey + " -out " + tmpKey + "-out"); err != nil {
			if strings.Contains(string(out), ":bad decrypt:") {
				return false, "Incorrect password"
			}

			return false, "Unable to load Root CA key"
		}

		if _, err := exeCmd("mv " + tmpKey + "-out " + tmpKey); err != nil {
			return false, err.Error()
		}
	}

	modKey, err := exeCmd("openssl rsa -noout -modulus -in " + tmpKey)
	if err != nil {
		return false, "Not a private key"
	}
	modCert, err := exeCmd("openssl x509 -noout -modulus -in " + path + certName + ".pem")
	if err != nil {
		return false, "Unable to load Root CA certificate"
	}
	if string(modKey) != string(modCert) {
		return false, "Key does not match the Root CA certificate"
	}

	if _, err := exeCmd("mv " + tmpKey + " " + path); err != nil {
		return false, err.Error()
	}

	return true, ""
}

func (ci *CertificateInfo) StoreRootKey(path string) bool {
	if ci.Errors == nil {
		ci.Errors = make(map[string]string)
	}
	if strings.TrimSpace(ci.Key) == "" {
		ci.Errors["Modal"] = "Please provide a PEM-encoded key"
		return false
	}

	tmpDir, err := os.MkdirTemp("", "labca")
	if err != nil {
		ci.Errors["Modal"] = err.Error()
		return false
	}

	defer os.RemoveAll(tmpDir)

	certBase := "root-01"
	if res, newError := storeRootKey(path, certBase, tmpDir, ci.Key, ci.Passphrase); !res {
		ci.Errors["Modal"] = newError
		return false
	}

	// Create root CRL file now that we have the key
	if _, err := exeCmd("openssl ca -config " + path + "openssl.cnf -gencrl -keyfile " + path + certBase + ".key -cert " + path + certBase + ".pem -out " + path + certBase + ".crl"); err != nil {
		fmt.Printf("StoreRootKey: %s\n", err.Error())
		return false
	}

	return true
}

func (ci *CertificateInfo) StoreCRL(path string) bool {
	if ci.Errors == nil {
		ci.Errors = make(map[string]string)
	}
	if strings.TrimSpace(ci.CRL) == "" {
		fmt.Println("WARNING: no Root CRL file provided - please upload one from the manage page")
		return true
	}

	tmpDir, err := os.MkdirTemp("", "labca")
	if err != nil {
		ci.Errors["Modal"] = err.Error()
		return false
	}

	defer os.RemoveAll(tmpDir)

	tmpCRL := filepath.Join(tmpDir, "root-ca.crl")

	if err := os.WriteFile(tmpCRL, []byte(ci.CRL), 0644); err != nil {
		ci.Errors["Modal"] = err.Error()
		return false
	}

	crlIssuer, err := exeCmd("openssl crl -noout -issuer -in " + tmpCRL)
	if err != nil {
		ci.Errors["Modal"] = "Not a CRL file"
		return false
	}
	rootSubj, err := exeCmd("openssl x509 -noout -subject -in " + path + "root-ca.pem")
	if err != nil {
		ci.Errors["Modal"] = "Cannot get Root CA subject"
		return false
	}

	if strings.TrimPrefix(string(crlIssuer), "issuer=") != strings.TrimPrefix(string(rootSubj), "subject=") {
		ci.Errors["Modal"] = "CRL file does not match the Root CA certificate"
		return false
	}

	if _, err := exeCmd("mv " + tmpCRL + " " + path); err != nil {
		ci.Errors["Modal"] = err.Error()
		return false
	}

	return true
}

func renewCertificate(certname string, days int, rootname string, _ string, _ string) error {
	ci := &CertificateInfo{
		IsRoot:  strings.HasPrefix(certname, "root-"),
		NumDays: days,
	}
	ci.Initialize()

	certFile := fmt.Sprintf("%s%s.pem", CERT_FILES_PATH, certname)
	rootCertFile := ""

	if !ci.IsRoot {
		rootCertFile = fmt.Sprintf("%s%s.pem", CERT_FILES_PATH, rootname)
	}

	seqnr := ""
	re := regexp.MustCompile(`-(\d{2})-`)
	match := re.FindStringSubmatch(certFile)
	if len(match) > 1 {
		seqnr = match[1]
	} else {
		return fmt.Errorf("failed to extract sequence number from filename '%s'", certFile)
	}

	rootseqnr := ""
	if !ci.IsRoot {
		match := re.FindStringSubmatch(rootCertFile)
		if len(match) > 1 {
			rootseqnr = match[1]
		} else {
			return fmt.Errorf("failed to extract sequence number from filename '%s'", rootCertFile)
		}
	}

	crt, err := readCertificate(certFile)
	if err != nil {
		return fmt.Errorf("failed to read current certificate: %w", err)
	}

	if crt.PublicKeyAlgorithm == x509.RSA {
		pub := crt.PublicKey.(*rsa.PublicKey)
		if pub.N.BitLen() == 2048 {
			ci.KeyType = "rsa2048"
		}
		if pub.N.BitLen() == 4096 {
			ci.KeyType = "rsa4096"
		}
	}
	if crt.PublicKeyAlgorithm == x509.ECDSA {
		if crt.SignatureAlgorithm == x509.ECDSAWithSHA256 {
			ci.KeyType = "ecdsa256"
		}
		if crt.SignatureAlgorithm == x509.ECDSAWithSHA384 {
			ci.KeyType = "ecdsa384"
		}
	}

	subjectMap := parseSubjectDn(crt.Subject.String())
	if val, ok := subjectMap["C"]; ok {
		ci.Country = val
	}
	if val, ok := subjectMap["O"]; ok {
		ci.Organization = val
	}
	if val, ok := subjectMap["CN"]; ok {
		ci.CommonName = val
	}

	if ci.IsRoot {
		_, err = ci.CeremonyRoot(seqnr, true)

		viper.Set("crl_root_days", ci.NumDays)
		viper.WriteConfig()
	} else {
		_, err = ci.CeremonyIssuer(seqnr, rootseqnr, true)
	}

	if err != nil {
		log.Printf("failed to create certificate: %s", err.Error())
		return errors.New("failed to create certificate, see logs for details")
	}

	if !ci.IsRoot {
		// Create CRLs stating that the intermediates are not revoked.
		err = ci.CeremonyRootCRL(rootseqnr)

		if err != nil {
			log.Printf("failed to create crl: %s", err.Error())
			return errors.New("failed to create crl, see logs for details")
		}
	}

	return nil
}

func locateFileIn(path, name string) string {
	if _, err := os.Stat(path + name); err == nil {
		return path + name
	}
	return ""
}

// TODO: sort out the file naming/locations properly to not need this and be future proof!!
// Most is found in /opt/boulder/ and some in /opt/boulder/labca/
func locateFile(name string) string {

	for _, path := range []string{"", "data/", "data/issuer", "/go/src/labca/data/", "/go/src/labca/data/issuer/", "labca/", "/opt/boulder/", "/opt/boulder/labca/"} {
		if res := locateFileIn(path, name); res != "" {
			return res
		}
	}

	fmt.Printf("WARNING: could not find '%s'!\n", name)
	return ""
}

func exeCmd(cmd string) ([]byte, error) {
	parts := strings.Fields(cmd)
	for i := 0; i < len(parts); i++ {
		parts[i] = strings.Replace(parts[i], "\\\\", " ", -1)
	}
	head := parts[0]
	parts = parts[1:]

	out, err := exec.Command(head, parts...).CombinedOutput()
	if err != nil {
		fmt.Print(fmt.Sprint(err) + ": " + string(out))
	}
	return out, err
}
