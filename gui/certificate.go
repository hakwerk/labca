package main

import (
    "errors"
    "fmt"
    "io"
    "io/ioutil"
    "mime/multipart"
    "os"
    "os/exec"
    "path/filepath"
    "runtime/debug"
    "strings"
)

type CertificateInfo struct {
    IsRoot     bool
    KeyTypes   map[string]string
    KeyType    string
    CreateType string

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

    RequestBase string
    Errors      map[string]string
}

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

func (ci *CertificateInfo) Validate() bool {
    ci.Errors = make(map[string]string)

    if ci.CreateType == "generate" {
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

func reportError(err error) error {
    lines := strings.Split(string(debug.Stack()), "\n")
    if len(lines) >= 5 {
        lines = append(lines[:0], lines[5:]...)
    }

    stop := len(lines)
    for i := 0; i < len(lines); i++ {
        if strings.Index(lines[i], ".ServeHTTP(") >= 0 {
            stop = i
            break
        }
    }
    lines = lines[:stop]
    lines = append(lines, "...")

    fmt.Println(strings.Join(lines, "\n"))

    return errors.New("Error (" + err.Error() + ")! See LabCA logs for details")
}

func preCreateTasks(path string) error {
    if _, err := exe_cmd("touch " + path + "index.txt"); err != nil {
        return reportError(err)
    }
    if _, err := exe_cmd("touch " + path + "index.txt.attr"); err != nil {
        return reportError(err)
    }

    if _, err := os.Stat(path + "serial"); os.IsNotExist(err) {
        if err := ioutil.WriteFile(path+"serial", []byte("1000\n"), 0644); err != nil {
            return err
        }
    }
    if _, err := os.Stat(path + "crlnumber"); os.IsNotExist(err) {
        if err = ioutil.WriteFile(path+"crlnumber", []byte("1000\n"), 0644); err != nil {
            return err
        }
    }

    if _, err := exe_cmd("mkdir -p " + path + "certs"); err != nil {
        return reportError(err)
    }

    return nil
}

func (ci *CertificateInfo) Create(path string, certBase string) error {
    if err := preCreateTasks(path); err != nil {
        return err
    }

    tmpDir, err := ioutil.TempDir("", "labca")
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

        if _, err := exe_cmd("openssl " + createCmd + " -out " + path + certBase + ".key" + keySize); err != nil {
            return reportError(err)
        }
        if _, err := exe_cmd("openssl pkey -in " + path + certBase + ".key -passin pass:foobar -out " + path + certBase + ".tmp"); err != nil {
            return reportError(err)
        }
        if _, err = exe_cmd("mv " + path + certBase + ".tmp " + path + certBase + ".key"); err != nil {
            return reportError(err)
        }

        _, _ = exe_cmd("sleep 1")

        // 2. Generate certificate
        subject := "/C=" + ci.Country + "/O=" + ci.Organization
        if ci.OrgUnit != "" {
            subject = subject + "/OU=" + ci.OrgUnit
        }
        subject = subject + "/CN=" + ci.CommonName
        subject = strings.Replace(subject, " ", "\\\\", -1)

        if ci.IsRoot {
            if _, err := exe_cmd("openssl req -config " + path + "openssl.cnf -days 3650 -new -x509 -extensions v3_ca -subj " + subject + " -key " + path + certBase + ".key -out " + path + certBase + ".pem"); err != nil {
                return reportError(err)
            }
        } else {
            if _, err := exe_cmd("openssl req -config " + path + "openssl.cnf -new -subj " + subject + " -key " + path + certBase + ".key -out " + path + certBase + ".csr"); err != nil {
                return reportError(err)
            }
            if _, err := exe_cmd("openssl ca -config " + path + "../openssl.cnf -extensions v3_intermediate_ca -days 3600 -md sha384 -notext -batch -in " + path + certBase + ".csr -out " + path + certBase + ".pem"); err != nil {
                return reportError(err)
            }
        }

    } else if ci.CreateType == "import" {
        tmpFile := filepath.Join(tmpDir, ci.ImportHandler.Filename)

        f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE, 0666)
        if err != nil {
            return err
        }

        defer f.Close()

        io.Copy(f, ci.ImportFile)

        contentType := ci.ImportHandler.Header.Get("Content-Type")
        if contentType == "application/x-pkcs12" {
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

            if out, err := exe_cmd("openssl pkcs12 -in " + strings.Replace(tmpFile, " ", "\\\\", -1) + " -password " + pwd + " -nocerts -nodes -out " + tmpKey); err != nil {
                if strings.Index(string(out), "invalid password") >= 0 {
                    return errors.New("Incorrect password!")
                } else {
                    return reportError(err)
                }
            }
            if out, err := exe_cmd("openssl pkcs12 -in " + strings.Replace(tmpFile, " ", "\\\\", -1) + " -password " + pwd + " -nokeys -out " + tmpCert); err != nil {
                if strings.Index(string(out), "invalid password") >= 0 {
                    return errors.New("Incorrect password!")
                } else {
                    return reportError(err)
                }
            }
        } else if contentType == "application/zip" {
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

            if _, err := exe_cmd(cmd); err != nil {
                if err.Error() == "exit status 82" {
                    return errors.New("Incorrect password!")
                } else {
                    return reportError(err)
                }
            }
        } else {
            return errors.New("Content Type '" + contentType + "' not supported!")
        }

    } else if ci.CreateType == "upload" {
        if err := ioutil.WriteFile(tmpKey, []byte(ci.Key), 0644); err != nil {
            return err
        }

        pwd := "pass:dummy"
        if ci.Passphrase != "" {
            pwd = "pass:" + strings.Replace(ci.Passphrase, " ", "\\\\", -1)
        }

        if out, err := exe_cmd("openssl pkey -passin " + pwd + " -in " + tmpKey + " -out " + tmpKey + "-out"); err != nil {
            if strings.Index(string(out), ":bad decrypt:") >= 0 {
                return errors.New("Incorrect password!")
            } else {
                return reportError(err)
            }
        } else {
            if _, err = exe_cmd("mv " + tmpKey + "-out " + tmpKey); err != nil {
                return reportError(err)
            }
        }

        if err := ioutil.WriteFile(tmpCert, []byte(ci.Certificate), 0644); err != nil {
            return err
        }

    } else {
        return fmt.Errorf("Unknown CreateType!")
    }

    // This is shared between pfx/zip upload and pem text upload
    if ci.CreateType != "generate" {
        var rootCert string
        var rootKey string
        var issuerCert string
        var issuerKey string

        if ci.IsRoot {
            rootCert = filepath.Join(tmpDir, "root-ca.pem")
            rootKey = filepath.Join(tmpDir, "root-ca.key")

            if _, err := os.Stat(rootCert); os.IsNotExist(err) {
                return errors.New("File does not contain root-ca.pem!")
            }
            if _, err := os.Stat(rootKey); os.IsNotExist(err) {
                return errors.New("File does not contain root-ca.key!")
            }
        }

        issuerCert = filepath.Join(tmpDir, "ca-int.pem")
        issuerKey = filepath.Join(tmpDir, "ca-int.key")

        if _, err := os.Stat(issuerCert); os.IsNotExist(err) {
            if ci.IsRoot {
                issuerCert = ""
            } else {
                return errors.New("File does not contain ca-int.pem!")
            }
        }
        if _, err := os.Stat(issuerKey); os.IsNotExist(err) {
            if ci.IsRoot {
                issuerKey = ""
            } else {
                return errors.New("File does not contain ca-int.key!")
            }
        }

        var rootSubject string
        if (rootCert != "") && (rootKey != "") {
            r, err := exe_cmd("openssl x509 -noout -subject -in " + rootCert)
            if err != nil {
                return reportError(err)
            } else {
                rootSubject = string(r[0 : len(r)-1])
                fmt.Printf("Import root with subject '%s'\n", rootSubject)
            }

            r, err = exe_cmd("openssl pkey -noout -in " + rootKey)
            if err != nil {
                return reportError(err)
            } else {
                fmt.Println("Import root key")
            }
        }

        if (issuerCert != "") && (issuerKey != "") {
            if ci.IsRoot {
                if err := preCreateTasks(path + "issuer/"); err != nil {
                    return err
                }
            }

            r, err := exe_cmd("openssl x509 -noout -subject -in " + issuerCert)
            if err != nil {
                return reportError(err)
            } else {
                fmt.Printf("Import issuer with subject '%s'\n", string(r[0:len(r)-1]))
            }

            r, err = exe_cmd("openssl x509 -noout -issuer -in " + issuerCert)
            if err != nil {
                return reportError(err)
            } else {
                issuerIssuer := string(r[0 : len(r)-1])
                fmt.Printf("Issuer certificate issued by CA '%s'\n", issuerIssuer)

                if rootSubject == "" {
                    r, err := exe_cmd("openssl x509 -noout -subject -in data/root-ca.pem")
                    if err != nil {
                        return reportError(err)
                    } else {
                        rootSubject = string(r[0 : len(r)-1])
                    }
                }

                issuerIssuer = strings.Replace(issuerIssuer, "issuer=", "", -1)
                rootSubject = strings.Replace(rootSubject, "subject=", "", -1)
                if issuerIssuer != rootSubject {
                    return errors.New("Issuer not issued by our Root CA!")
                }
            }

            r, err = exe_cmd("openssl pkey -noout -in " + issuerKey)
            if err != nil {
                return reportError(err)
            } else {
                fmt.Println("Import issuer key")
            }
        }

        // All is good now, move files to their permanent location...
        if rootCert != "" {
            if _, err = exe_cmd("mv " + rootCert + " " + path); err != nil {
                return reportError(err)
            }
        }
        if rootKey != "" {
            if _, err = exe_cmd("mv " + rootKey + " " + path); err != nil {
                return reportError(err)
            }
        }
        if issuerCert != "" {
            if _, err = exe_cmd("mv " + issuerCert + " data/issuer/"); err != nil {
                return reportError(err)
            }
        }
        if issuerKey != "" {
            if _, err = exe_cmd("mv " + issuerKey + " data/issuer/"); err != nil {
                return reportError(err)
            }
        }

        if (issuerCert != "") && (issuerKey != "") && ci.IsRoot {
            if err := postCreateTasks(path+"issuer/", "ca-int"); err != nil {
                return err
            }
        }
    }

    if err := postCreateTasks(path, certBase); err != nil {
        return err
    }

    if ci.IsRoot {
        if _, err := exe_cmd("openssl ca -config " + path + "openssl.cnf -gencrl -keyfile " + path + certBase + ".key -cert " + path + certBase + ".pem -out " + path + certBase + ".crl"); err != nil {
            return reportError(err)
        }
    }

    return nil
}

func postCreateTasks(path string, certBase string) error {
    if _, err := exe_cmd("openssl pkey -in " + path + certBase + ".key -out " + path + certBase + ".key.der -outform der"); err != nil {
        return reportError(err)
    }

    if _, err := exe_cmd("openssl x509 -in " + path + certBase + ".pem -out " + path + certBase + ".der -outform DER"); err != nil {
        return reportError(err)
    }

    return nil
}

func exe_cmd(cmd string) ([]byte, error) {
    parts := strings.Fields(cmd)
    for i := 0; i < len(parts); i++ {
        parts[i] = strings.Replace(parts[i], "\\\\", " ", -1)
    }
    head := parts[0]
    parts = parts[1:]

    out, err := exec.Command(head, parts...).CombinedOutput()
    if err != nil {
        fmt.Print(fmt.Sprint(err) + ": " + string(out))
    } else {
        //fmt.Println(string(out))
    }
    return out, err
}
