package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func CheckUpgrades() {
	v := viper.GetString("version")
	if standaloneVersion == "" {
		gitVersion := controlCommand("git-version", true)
		if gitVersion != "" {
			viper.Set("version", strings.TrimSpace(gitVersion))
			viper.WriteConfig()
		}
	} else if v != standaloneVersion {
		viper.Set("version", standaloneVersion)
		viper.WriteConfig()
	}

	changed := CheckUpgrade_01_CeremonyHSM()

	if changed {
		time.Sleep(2 * time.Second)
		log.Println("Applying updated configuration...")
		controlCommand("apply", false)
		time.Sleep(2 * time.Second)
		log.Println("Updating CRL links if needed...")
		controlCommand("check-crl", false)
		time.Sleep(2 * time.Second)
		log.Println("Restarting boulder containers...")
		controlCommand("boulder-restart", false)
	}
}

func readFileAsString(filename string) string {
	read, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("**** Could not read '%s': %s\n", filename, err.Error())
		log.Println("**** ABORT MIGRATION ****")
		time.Sleep(1 * time.Minute)
		os.Exit(1)
	}

	return string(read)
}

func controlCommand(command string, ignoreError bool) string {
	conn, err := net.Dial("tcp", "control:3030")
	if err != nil {
		if ignoreError {
			return ""
		}
		log.Println("**** Failed to connect to control container!")
		time.Sleep(1 * time.Minute)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprint(conn, command+"\n")

	reader := bufio.NewReader(conn)
	message, err := io.ReadAll(reader)
	if err != nil {
		log.Printf("**** Failed to read response from control container: %s\n", err.Error())
		time.Sleep(1 * time.Minute)
		os.Exit(1)
	}

	if len(message) >= 4 {
		tail := message[len(message)-4:]
		if strings.Compare(string(tail), "\nok\n") == 0 {
			msg := message[0 : len(message)-4]
			log.Printf("**** Message from control server: '%s'", msg)
		}
	}

	return string(message)
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}

	err = destinationFile.Sync()
	if err != nil {
		return err
	}

	return nil
}

// Check if we should upgrade to using the Ceremony tool and store keys on SoftHSM (January 2025).
func CheckUpgrade_01_CeremonyHSM() bool {
	baseDir := "/opt/labca/data/"
	prevRootCert := baseDir + "root-ca.pem"
	if _, err := os.Stat(prevRootCert); errors.Is(err, fs.ErrNotExist) {
		baseDir = "/go/src/labca/data/"
		prevRootCert = baseDir + "root-ca.pem"
		if _, err := os.Stat(prevRootCert); errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}

	log.Println("**** BEGIN MIGRATION: upgrade01 ****")

	rootCertFile := fmt.Sprintf("%sroot-01-cert.pem", CERT_FILES_PATH)
	if _, err := os.Stat(rootCertFile); !errors.Is(err, fs.ErrNotExist) {
		log.Printf("**** File %s already exists!\n", rootCertFile)
		log.Println("**** ABORT MIGRATION ****")
		time.Sleep(1 * time.Minute)
		os.Exit(1)
	}

	prevRootKey := baseDir + "root-ca.key"
	if _, err := os.Stat(prevRootKey); errors.Is(err, fs.ErrNotExist) {
		log.Println("**** Root key file not present on the system: cannot upgrade automatically!")
		log.Println("**** Please do a fresh install of LabCA and import / upload the root certificate and key.")
		log.Println("**** ABORT MIGRATION ****")
		time.Sleep(1 * time.Minute)
		os.Exit(1)
	}

	// Migrate root certificate and key
	ci := &CertificateInfo{IsRoot: true}
	ci.Initialize()
	ci.IsRoot = true
	ci.CreateType = "upload"
	ci.Certificate = readFileAsString(prevRootCert)
	ci.Key = readFileAsString(prevRootKey)
	prevRootCRL := baseDir + "root-ca.crl"
	if _, err := os.Stat(prevRootCRL); !errors.Is(err, fs.ErrNotExist) {
		ci.CRL = readFileAsString(prevRootCRL)
		copyFile(prevRootCRL, strings.Replace(rootCertFile, "-cert.", "-crl.", -1))
	}

	if err := ci.Create("root-01", false); err != nil {
		log.Printf("**** Could not convert previous root certificate and key: %s\n", err.Error())
		log.Println("**** ABORT MIGRATION ****")
		time.Sleep(1 * time.Minute)
		os.Exit(1)
	}

	// Migrate issuer certificate and key
	ci = &CertificateInfo{IsRoot: false}
	ci.Initialize()
	ci.IsRoot = false
	ci.CreateType = "upload"
	prevIssuerCert := baseDir + "issuer/ca-int.pem"
	ci.Certificate = readFileAsString(prevIssuerCert)
	prevIssuerKey := baseDir + "issuer/ca-int.key"
	ci.Key = readFileAsString(prevIssuerKey)
	ci.CRL = ""

	if err := ci.Create("issuer-01", false); err != nil {
		log.Printf("**** Could not convert previous issuer certificate and key: %s\n", err.Error())
		log.Println("**** ABORT MIGRATION ****")
		time.Sleep(1 * time.Minute)
		os.Exit(1)
	}

	os.Rename(prevRootCert, prevRootCert+"_backup")
	os.Rename(prevRootKey, prevRootKey+"_backup")
	os.Rename(prevRootCRL, prevRootCRL+"_backup")
	os.Rename(prevIssuerCert, prevIssuerCert+"_backup")
	os.Rename(prevIssuerKey, prevIssuerKey+"_backup")

	log.Println("**** END MIGRATION ****")
	return true
}
