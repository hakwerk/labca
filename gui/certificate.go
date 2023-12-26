package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/big"
	"mime/multipart"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
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
	OrgUnit      string
	CommonName   string

	ImportFile    multipart.File
	ImportHandler *multipart.FileHeader
	ImportPwd     string

	Key         string
	Passphrase  string
	Certificate string
	CRL         string

	RequestBase string
	Errors      map[string]string
}

// Initialize the CertificateInfo and set the list of available key types
func (ci *CertificateInfo) Initialize() {
	ci.Errors = make(map[string]string)

	ci.KeyTypes = make(map[string]string)
	ci.KeyTypes["rsa4096"] = "RSA-4096"
	ci.KeyTypes["rsa3072"] = "RSA-3072"
	ci.KeyTypes["rsa2048"] = "RSA-2048"
	ci.KeyTypes["ecdsa384"] = "ECDSA-384"
	ci.KeyTypes["ecdsa256"] = "ECDSA-256"

	ci.KeyType = "rsa4096"
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
		if !ci.IsRoot && strings.TrimSpace(ci.Key) == "" {
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

func getRandomSerial() (string, error) {
	// from ca.generateSerialNumberAndValidity()
	const randBits = 136
	serialBytes := make([]byte, randBits/8+1)
	serialBytes[0] = 0xee
	if _, err := rand.Read(serialBytes[1:]); err != nil {
		return "", reportError(err)
	}

	serialBigInt := big.NewInt(0)
	serialBigInt.SetBytes(serialBytes)

	return fmt.Sprintf("%x", serialBigInt), nil
}

func preCreateTasks(path string) error {
	if _, err := exeCmd("touch " + path + "index.txt"); err != nil {
		return reportError(err)
	}
	if _, err := exeCmd("touch " + path + "index.txt.attr"); err != nil {
		return reportError(err)
	}

	if _, err := os.Stat(path + "serial"); errors.Is(err, fs.ErrNotExist) {
		s, err := getRandomSerial()
		if err != nil {
			return err
		}
		if err := os.WriteFile(path+"serial", []byte(s+"\n"), 0644); err != nil {
			return err
		}
	}
	if _, err := os.Stat(path + "crlnumber"); errors.Is(err, fs.ErrNotExist) {
		if err = os.WriteFile(path+"crlnumber", []byte("1000\n"), 0644); err != nil {
			return err
		}
	}

	if _, err := exeCmd("mkdir -p " + path + "certs"); err != nil {
		return reportError(err)
	}

	return nil
}

func updateRootCRLDays(filename string, numDays int) error {
	read, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return errors.New("could not read '" + filename + "': " + err.Error())
	}
	re := regexp.MustCompile(`(default_crl_days\s*=).*`)
	res := re.ReplaceAll(read, []byte("$1 "+strconv.Itoa(numDays)))

	if err = os.WriteFile(filename, res, 0640); err != nil {
		fmt.Println(err)
		return errors.New("could not write '" + filename + "': " + err.Error())
	}

	return nil
}

// Generate a key and certificate file for the data from this CertificateInfo
func (ci *CertificateInfo) Generate(path string, certBase string) error {
	// 1. Generate key
	createCmd := "genrsa -aes256 -passout pass:foobar"
	keySize := " 4096"
	if strings.HasPrefix(ci.KeyType, "ecdsa") {
		keySize = ""
		createCmd = "ecparam -genkey -name "
		if ci.KeyType == "ecdsa256" {
			createCmd = createCmd + "prime256v1"
		}
		if ci.KeyType == "ecdsa384" {
			createCmd = createCmd + "secp384r1"
		}
	} else {
		if strings.HasSuffix(ci.KeyType, "3072") {
			keySize = " 3072"
		}
		if strings.HasSuffix(ci.KeyType, "2048") {
			keySize = " 2048"
		}
	}

	if _, err := exeCmd("openssl " + createCmd + " -out " + path + certBase + ".key" + keySize); err != nil {
		return reportError(err)
	}
	if _, err := exeCmd("openssl pkey -in " + path + certBase + ".key -passin pass:foobar -out " + path + certBase + ".tmp"); err != nil {
		return reportError(err)
	}
	if _, err := exeCmd("mv " + path + certBase + ".tmp " + path + certBase + ".key"); err != nil {
		return reportError(err)
	}

	_, _ = exeCmd("sleep 1")

	// 2. Generate certificate
	subject := "/C=" + ci.Country + "/O=" + ci.Organization
	if ci.OrgUnit != "" {
		subject = subject + "/OU=" + ci.OrgUnit
	}
	subject = subject + "/CN=" + ci.CommonName
	subject = strings.Replace(subject, " ", "\\\\", -1)

	if ci.IsRoot {
		if _, err := exeCmd("openssl req -config " + path + "openssl.cnf -days " + strconv.Itoa(ci.NumDays) + " -new -utf8 -x509 -extensions v3_ca -subj " + subject + " -key " + path + certBase + ".key -out " + path + certBase + ".pem"); err != nil {
			return reportError(err)
		}

		if err := updateRootCRLDays(path+"openssl.cnf", ci.NumDays); err != nil {
			return reportError(err)
		}
	} else {
		if _, err := exeCmd("openssl req -config " + path + "openssl.cnf -new -utf8 -subj " + subject + " -key " + path + certBase + ".key -out " + path + certBase + ".csr"); err != nil {
			return reportError(err)
		}
		if out, err := exeCmd("openssl ca -config " + path + "../openssl.cnf -extensions v3_intermediate_ca -days " + strconv.Itoa(ci.NumDays) + " -md sha384 -notext -batch -in " + path + certBase + ".csr -out " + path + certBase + ".pem"); err != nil {
			if strings.Contains(string(out), "root-ca.key for reading, No such file or directory") {
				return errors.New("NO_ROOT_KEY")
			}
			return reportError(err)
		}
	}

	return nil
}

// ImportPkcs12 imports an uploaded PKCS#12 / PFX file
func (ci *CertificateInfo) ImportPkcs12(tmpFile string, tmpKey string, tmpCert string) error {
	if ci.IsRoot {
		if strings.Index(ci.ImportHandler.Filename, "labca_root") != 0 {
			fmt.Printf("WARNING: importing root from .pfx file but name is %s\n", ci.ImportHandler.Filename)
		}
	} else {
		if strings.Index(ci.ImportHandler.Filename, "labca_issuer") != 0 {
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
		if (strings.Index(ci.ImportHandler.Filename, "labca_root") != 0) && (strings.Index(ci.ImportHandler.Filename, "labca_certificates") != 0) {
			fmt.Printf("WARNING: importing root from .zip file but name is %s\n", ci.ImportHandler.Filename)
		}
	} else {
		if strings.Index(ci.ImportHandler.Filename, "labca_issuer") != 0 {
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

// ImportCerts imports both the root and the issuer certificates
func (ci *CertificateInfo) ImportCerts(path string, rootCert string, rootKey string, issuerCert string, issuerKey string) error {
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
		if val, ok := subjectMap["OU"]; ok {
			ci.OrgUnit = val
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
		if ci.IsRoot {
			if err := preCreateTasks(path + "issuer/"); err != nil {
				return err
			}
		}

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
			r, err := exeCmd("openssl x509 -noout -subject -in data/root-ca.pem")
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

		_, err = exeCmd("openssl verify -CAfile data/root-ca.pem " + issuerCert)
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

// MoveFiles moves certificate / key files to their final location
func (ci *CertificateInfo) MoveFiles(path string, rootCert string, rootKey string, issuerCert string, issuerKey string) error {
	if rootCert != "" {
		if _, err := exeCmd("mv " + rootCert + " " + path); err != nil {
			return reportError(err)
		}
	}
	if rootKey != "" {
		keyFileExists := true
		if _, err := os.Stat(rootKey); errors.Is(err, fs.ErrNotExist) {
			keyFileExists = false
		}
		if keyFileExists {
			if _, err := exeCmd("mv " + rootKey + " " + path); err != nil {
				return reportError(err)
			}
		}
	}
	if issuerCert != "" {
		if _, err := exeCmd("mv " + issuerCert + " data/issuer/"); err != nil {
			return reportError(err)
		}
	}
	if issuerKey != "" {
		if _, err := exeCmd("mv " + issuerKey + " data/issuer/"); err != nil {
			return reportError(err)
		}
	}

	if (issuerCert != "") && (issuerKey != "") && ci.IsRoot {
		if err := postCreateTasks(path+"issuer/", "ca-int", false); err != nil {
			return err
		}
	}

	return nil
}

// Extract key and certificate files from a container file
func (ci *CertificateInfo) Extract(path string, certBase string, tmpDir string, wasCSR bool) error {
	var rootCert string
	var rootKey string
	var issuerCert string
	var issuerKey string

	if ci.IsRoot {
		rootCert = filepath.Join(tmpDir, "root-ca.pem")
		rootKey = filepath.Join(tmpDir, "root-ca.key")

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
				return errors.New("file does not contain root-ca.pem")
			}
		}
	}

	issuerCert = filepath.Join(tmpDir, "ca-int.pem")
	issuerKey = filepath.Join(tmpDir, "ca-int.key")

	if _, err := os.Stat(issuerCert); errors.Is(err, fs.ErrNotExist) {
		if ci.IsRoot {
			issuerCert = ""
		} else {
			altCert := filepath.Join(tmpDir, "test-ca.pem")
			if _, err = os.Stat(altCert); err == nil {
				if _, err := exeCmd("mv " + altCert + " " + issuerCert); err != nil {
					return err
				}
			}

			if _, err := os.Stat(issuerCert); errors.Is(err, fs.ErrNotExist) {
				return errors.New("file does not contain ca-int.pem")
			}
		}
	}
	if _, err := os.Stat(issuerKey); errors.Is(err, fs.ErrNotExist) {
		if ci.IsRoot || wasCSR {
			issuerKey = ""
		} else {
			altKey := filepath.Join(tmpDir, "test-ca.key")
			if _, err = os.Stat(altKey); err == nil {
				if _, err := exeCmd("mv " + altKey + " " + issuerKey); err != nil {
					return err
				}
			}

			if _, err := os.Stat(issuerKey); errors.Is(err, fs.ErrNotExist) {
				return errors.New("file does not contain ca-int.key")
			}
		}
	}

	err := ci.ImportCerts(path, rootCert, rootKey, issuerCert, issuerKey)
	if err != nil {
		return err
	}

	// All is good now, move files to their permanent location...
	err = ci.MoveFiles(path, rootCert, rootKey, issuerCert, issuerKey)
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
		if err := updateRootCRLDays("data/openssl.cnf", int(math.Ceil(numDays))); err != nil {
			return err
		}
	}

	return nil
}

// Create a new pair of key + certificate files based on the info in CertificateInfo
func (ci *CertificateInfo) Create(path string, certBase string, wasCSR bool) error {
	if err := preCreateTasks(path); err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "labca")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tmpDir)

	var tmpKey string
	var tmpCert string
	if ci.IsRoot {
		tmpKey = filepath.Join(tmpDir, "root-ca.key")
		tmpCert = filepath.Join(tmpDir, "root-ca.pem")
	} else {
		tmpKey = filepath.Join(tmpDir, "ca-int.key")
		tmpCert = filepath.Join(tmpDir, "ca-int.pem")
	}

	if ci.CreateType == "generate" {
		err := ci.Generate(path, certBase)
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
		err := ci.Extract(path, certBase, tmpDir, wasCSR)
		if err != nil {
			return err
		}
	}

	if err := postCreateTasks(path, certBase, ci.IsRoot); err != nil {
		return err
	}

	if ci.IsRoot {
		keyFileExists := true
		if _, err := os.Stat(path + certBase + ".key"); errors.Is(err, fs.ErrNotExist) {
			keyFileExists = false
		}
		if keyFileExists {
			if _, err := exeCmd("openssl ca -config " + path + "openssl.cnf -gencrl -keyfile " + path + certBase + ".key -cert " + path + certBase + ".pem -out " + path + certBase + ".crl"); err != nil {
				return reportError(err)
			}
		}
	}

	return nil
}

func postCreateTasks(path string, certBase string, isRoot bool) error {
	if !isRoot {
		if _, err := exeCmd("openssl pkey -in " + path + certBase + ".key -out " + path + certBase + ".key.der -outform der"); err != nil {
			return reportError(err)
		}
	}

	if _, err := exeCmd("openssl x509 -in " + path + certBase + ".pem -out " + path + certBase + ".der -outform DER"); err != nil {
		return reportError(err)
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

	certBase := "root-ca"
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

func renewCertificate(certname string, days int, rootname string, rootkeyfile string, passphrase string) error {
	certFile := locateFile(certname + ".pem")
	path := filepath.Dir(certFile) + "/"
	certBase := path + certname
	keyFile := certBase + ".key"
	rootCert := ""
	rootKey := keyFile

	if strings.HasPrefix(certname, "ca-int") || strings.HasPrefix(certname, "test-ca") {
		rootCert = locateFile(rootname + ".pem")
		rootKey = locateFile(rootname + ".key")

		// Make sure openssl allows us to add certificates with the same subject
		attrFile := "data/index.txt.attr"
		read, err := os.ReadFile(attrFile)
		if err != nil {
			fmt.Println(err)
			return errors.New("could not read index.txt.attr file: " + err.Error())
		}
		re := regexp.MustCompile(`unique_subject = yes`)
		res := re.ReplaceAll(read, []byte("unique_subject = no"))

		if string(res) != string(read) {
			if err = os.WriteFile(attrFile, res, 0640); err != nil {
				fmt.Println(err)
				return errors.New("could not write index.txt.attr file: " + err.Error())
			}
		}
	}

	tmpDir, err := os.MkdirTemp("", "labca")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tmpDir)

	if _, err := os.Stat(rootKey); errors.Is(err, fs.ErrNotExist) {
		if rootkeyfile == "" {
			return errors.New("NO_ROOT_KEY")
		} else {
			if res, newError := storeRootKey(path, certname, tmpDir, rootkeyfile, passphrase); !res {
				return errors.New("NO_ROOT_KEY:" + newError)
			}
			defer exeCmd("rm " + rootKey)
		}
	}

	r, err := exeCmd("openssl x509 -noout -subject -nameopt utf8 -in " + certFile)
	if err != nil {
		return err
	}
	subject := string(r[8 : len(r)-1])
	subject = "/" + strings.ReplaceAll(subject, ", ", "/")
	subject = strings.Replace(subject, " ", "\\\\", -1)

	if rootKey == keyFile {
		if _, err := exeCmd("openssl req -config data/openssl.cnf -days " + strconv.Itoa(days) + " -new -utf8 -x509 -extensions v3_ca -subj " + subject +
			" -key " + keyFile + " -out " + certFile + ".tmp"); err != nil {
			return reportError(err)
		}

		if err := updateRootCRLDays("data/openssl.cnf", days); err != nil {
			return reportError(err)
		}

		if _, err := exeCmd("openssl ca -config data/openssl.cnf -gencrl -keyfile " + keyFile + " -cert " + certFile + ".tmp -out " + certBase + ".crl"); err != nil {
			return reportError(err)
		}

	} else {
		if _, err := exeCmd("openssl req -config data/issuer/openssl.cnf -new -utf8 -subj " + subject + " -key " + keyFile + " -out " + certBase + ".csr"); err != nil {
			return reportError(err)
		}
		if out, err := exeCmd("openssl ca -config data/openssl.cnf -cert " + rootCert + " -keyfile " + rootKey + " -extensions v3_intermediate_ca -days " +
			strconv.Itoa(days) + " -md sha384 -notext -batch -in " + certBase + ".csr -out " + certFile + ".tmp"); err != nil {
			if strings.Contains(string(out), ".key for reading, No such file or directory") {
				fmt.Println(out)
				return errors.New("NO_ROOT_KEY")
			}
			return reportError(err)
		}

	}
	if _, err := exeCmd("mv " + certFile + ".tmp " + certFile); err != nil {
		return reportError(err)
	}

	// TODO: need to get rid of this!
	if rootKey == keyFile {
		if strings.HasPrefix(certname, "test-root") {
			dataFile := locateFile("root-ca.pem")
			if _, err := exeCmd("cp " + certFile + " " + dataFile); err != nil {
				fmt.Println(err)
			}
			dataKeyFile := strings.TrimSuffix(dataFile, filepath.Ext(dataFile)) + ".key"
			if _, err := exeCmd("cp " + keyFile + " " + dataKeyFile); err != nil {
				fmt.Println(err)
			}
			crlFile := strings.TrimSuffix(dataFile, filepath.Ext(dataFile)) + ".crl"
			if _, err := exeCmd("cp " + certBase + ".crl " + crlFile); err != nil {
				fmt.Println(err)
			}
		}
	} else {
		if strings.HasPrefix(certname, "test-ca") {
			dataFile := locateFile("ca-int.pem")
			if _, err := exeCmd("cp " + certFile + " " + dataFile); err != nil {
				fmt.Println(err)
			}
			dataKeyFile := strings.TrimSuffix(dataFile, filepath.Ext(dataFile)) + ".key"
			if _, err := exeCmd("cp " + keyFile + " " + dataKeyFile); err != nil {
				fmt.Println(err)
			}
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