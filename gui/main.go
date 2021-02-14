package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/biz/templates"
	"github.com/dustin/go-humanize"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/go-github/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	updateInterval = 24 * time.Hour
)

var (
	appSession      *sessions.Session
	restartSecret   string
	sessionStore    *sessions.CookieStore
	tmpls           *templates.Templates
	version         string
	dbConn          string
	dbType          string
	isDev           bool
	updateAvailable bool
	updateChecked   time.Time

	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

// User struct for storing the admin user account details.
type User struct {
	Name        string
	Email       string
	Password    string
	Confirm     string
	NewPassword string
	RequestBase string
	Errors      map[string]string
}

// ValidatePassword checks that the password of a User is non-empty, matches the confirmation, is not on the blacklist and is sufficiently complex.
func (reg *User) ValidatePassword(isNew bool, isChange bool) {
	blacklist := []string{"labca", "acme", reg.Name}
	if x := strings.Index(reg.Email, "@"); x > 0 {
		blacklist = append(blacklist, reg.Email[:x])
		d := strings.Split(reg.Email[x+1:], ".")
		for i := 0; i < len(d)-1; i++ {
			blacklist = append(blacklist, d[i])
		}
	}

	if strings.TrimSpace(reg.Password) == "" {
		reg.Errors["Password"] = "Please enter a password"
	} else if isNew {
		strength := zxcvbn.PasswordStrength(reg.Password, blacklist).Score
		if strength < 1 {
			reg.Errors["Password"] = "Please pick a stronger, more secure password"
		}
	}

	if isNew {
		if strings.TrimSpace(reg.Confirm) == "" {
			reg.Errors["Confirm"] = "Please enter the password again"
		} else if strings.TrimSpace(reg.Confirm) != strings.TrimSpace(reg.Password) {
			reg.Errors["Confirm"] = "Passwords do not match!"
		}
	}

	if isChange {
		if strings.TrimSpace(reg.NewPassword) != "" {
			strength := zxcvbn.PasswordStrength(reg.NewPassword, blacklist).Score
			if strength < 1 {
				reg.Errors["NewPassword"] = "Please pick a stronger, more secure password"
			}

			if strings.TrimSpace(reg.Confirm) == "" {
				reg.Errors["Confirm"] = "Please enter the new password again"
			} else if strings.TrimSpace(reg.Confirm) != strings.TrimSpace(reg.NewPassword) {
				reg.Errors["Confirm"] = "New passwords do not match!"
			}
		}

		byteStored := []byte(viper.GetString("user.password"))
		err := bcrypt.CompareHashAndPassword(byteStored, []byte(reg.Password))
		if err != nil {
			reg.Errors["Password"] = "Current password is not correct!"
		}
	}
}

// Validate that User struct contains at least a Name, has a valid email address and password fields.
func (reg *User) Validate(isNew bool, isChange bool) bool {
	reg.Errors = make(map[string]string)

	if strings.TrimSpace(reg.Name) == "" {
		reg.Errors["Name"] = "Please enter a user name"
	}

	if isNew || isChange {
		re := regexp.MustCompile(".+@.+\\..+")
		matched := re.Match([]byte(reg.Email))
		if matched == false {
			reg.Errors["Email"] = "Please enter a valid email address"
		}
	}

	reg.ValidatePassword(isNew, isChange)

	return len(reg.Errors) == 0
}

// SetupConfig stores the basic config settings.
type SetupConfig struct {
	Fqdn             string
	Organization     string
	DNS              string
	DomainMode       string
	LockdownDomains  string
	WhitelistDomains string
	ExtendedTimeout  bool
	RequestBase      string
	Errors           map[string]string
}

// Validate that SetupConfig contains all required data.
func (cfg *SetupConfig) Validate(orgRequired bool) bool {
	cfg.Errors = make(map[string]string)

	if strings.TrimSpace(cfg.Fqdn) == "" {
		cfg.Errors["Fqdn"] = "Please enter the Fully Qualified Domain name for this host"
	}

	if strings.TrimSpace(cfg.Organization) == "" && orgRequired {
		cfg.Errors["Organization"] = "Please enter the organization name to show on the public pages"
	}

	if strings.TrimSpace(cfg.DNS) == "" {
		cfg.Errors["DNS"] = "Please enter the DNS server to be used for validation"
	}

	if cfg.DomainMode != "lockdown" && cfg.DomainMode != "whitelist" && cfg.DomainMode != "standard" {
		cfg.Errors["DomainMode"] = "Please select the domain mode to use"
	}

	if cfg.DomainMode == "lockdown" && strings.TrimSpace(cfg.LockdownDomains) == "" {
		cfg.Errors["LockdownDomains"] = "Please enter one or more domains that this PKI host is locked down to"
	}

	if cfg.DomainMode == "whitelist" && strings.TrimSpace(cfg.WhitelistDomains) == "" {
		cfg.Errors["WhitelistDomains"] = "Please enter one or more domains that are whitelisted for this PKI host"
	}

	return len(cfg.Errors) == 0
}

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	if appSession != nil {
		return appSession
	}

	session, err := sessionStore.Get(r, "labca")
	if err != nil {
		// Create new session
		session = sessions.NewSession(sessionStore, "labca")
		session.Save(r, w)
	}

	appSession = session
	return appSession
}

func errorHandler(w http.ResponseWriter, r *http.Request, err error, status int) {
	log.Printf("errorHandler: %v", err)

	w.WriteHeader(status)

	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	//fmt.Printf("%s:%d, %s\n", frame.File, frame.Line, frame.Function)

	if frame.Function == "main.render" {
		fmt.Fprintf(w, "Could not render requested page")
		return
	}

	if status == http.StatusNotFound {
		render(w, r, "error", map[string]interface{}{"Message": "That page does not exist"})
	} else {
		lines := strings.Split(string(debug.Stack()), "\n")
		if len(lines) >= 5 {
			lines = append(lines[:0], lines[5:]...)
		}
		fmt.Print(strings.Join(lines, "\n"))

		render(w, r, "error", map[string]interface{}{"Message": "Some unexpected error occurred!"})
		// TODO: send email eventually with info on the error
	}
}

func checkUpdates(forced bool) ([]string, []string) {
	var versions []string
	var descriptions []string

	if forced || updateChecked.Add(updateInterval).Before(time.Now()) {
		latest := ""
		newer := true

		client := github.NewClient(nil)

		if releases, _, err := client.Repositories.ListReleases(context.Background(), "hakwerk", "labca", nil); err == nil {
			for i := 0; i < len(releases); i++ {
				release := releases[i]
				if !*release.Draft {
					if !*release.Prerelease || isDev {
						if latest == "" {
							latest = *release.Name
						}
						if *release.Name == version {
							newer = false
						}
						if latest == *release.Name && strings.HasPrefix(version, *release.Name+"-") { // git describe format
							newer = false
							latest = version
						}
						if newer {
							versions = append(versions, *release.Name)
							descriptions = append(descriptions, *release.Body)
						}
					}
				}
			}

			updateChecked = time.Now()
			updateAvailable = (len(releases) > 0) && (latest != version)
		}
	}

	return versions, descriptions
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	dashboardData, err := CollectDashboardData(w, r)
	if err == nil {
		checkUpdates(false)
		dashboardData["UpdateAvailable"] = updateAvailable
		dashboardData["UpdateChecked"] = strings.Replace(updateChecked.Format("02-Jan-2006 15:04:05 MST"), "+0000", "GMT", -1)
		dashboardData["UpdateCheckedRel"] = humanize.RelTime(updateChecked, time.Now(), "", "")

		render(w, r, "dashboard", dashboardData)
	}
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	render(w, r, "about", map[string]interface{}{
		"Title": "About",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if viper.Get("user.password") == nil {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	session := getSession(w, r)
	var bounceURL string
	if session.Values["bounce"] == nil {
		bounceURL = "/"
	} else {
		bounceURL = session.Values["bounce"].(string)
	}

	if session.Values["user"] != nil {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+bounceURL, http.StatusFound)
		return
	}

	if r.Method == "GET" {
		reg := &User{
			RequestBase: r.Header.Get("X-Request-Base"),
		}
		render(w, r, "login", map[string]interface{}{"User": reg, "IsLogin": true})
		return
	} else if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return
		}

		reg := &User{
			Name:        r.Form.Get("username"),
			Password:    r.Form.Get("password"),
			RequestBase: r.Header.Get("X-Request-Base"),
		}

		if reg.Validate(false, false) == false {
			render(w, r, "login", map[string]interface{}{"User": reg, "IsLogin": true})
			return
		}

		if viper.GetString("user.name") != reg.Name {
			reg.Errors["Name"] = "Incorrect username or password"
			render(w, r, "login", map[string]interface{}{"User": reg, "IsLogin": true})
			return
		}

		byteStored := []byte(viper.GetString("user.password"))
		err := bcrypt.CompareHashAndPassword(byteStored, []byte(reg.Password))
		if err != nil {
			log.Println(err)
			reg.Errors["Name"] = "Incorrect username or password"
			render(w, r, "login", map[string]interface{}{"User": reg, "IsLogin": true})
			return
		}

		session.Values["user"] = reg.Name
		session.Save(r, w)

		http.Redirect(w, r, r.Header.Get("X-Request-Base")+bounceURL, http.StatusFound)
	} else {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/login", http.StatusSeeOther)
		return
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	appSession = nil
	http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/", http.StatusFound)
}

func _sendCmdOutput(w http.ResponseWriter, r *http.Request, cmd string) {
	parts := strings.Fields(cmd)
	for i := 0; i < len(parts); i++ {
		parts[i] = strings.Replace(parts[i], "\\\\", " ", -1)
	}
	head := parts[0]
	parts = parts[1:]

	out, err := exec.Command(head, parts...).Output()
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return
	}

	buf := bytes.NewBuffer(out)
	_, err = buf.WriteTo(w)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return
	}
}

func _backupHandler(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Success bool
		Message string
	}{Success: true}

	action := r.Form.Get("action")
	if action == "backup-restore" {
		backup := r.Form.Get("backup")
		if !_hostCommand(w, r, action, backup) {
			res.Success = false
			res.Message = "Command failed - see LabCA log for any details"
		}

		defer _hostCommand(w, r, "server-restart")
	} else if action == "backup-delete" {
		backup := r.Form.Get("backup")
		if !_hostCommand(w, r, action, backup) {
			res.Success = false
			res.Message = "Command failed - see LabCA log for any details"
		}
	} else if action == "backup-now" {
		res.Message = getLog(w, r, "server-backup")
		if res.Message == "" {
			res.Success = false
			res.Message = "Command failed - see LabCA log for any details"
		} else {
			res.Message = filepath.Base(res.Message)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func _accountUpdateHandler(w http.ResponseWriter, r *http.Request) {
	reg := &User{
		Name:        r.Form.Get("username"),
		Email:       r.Form.Get("email"),
		NewPassword: r.Form.Get("new-password"),
		Confirm:     r.Form.Get("confirm"),
		Password:    r.Form.Get("password"),
	}

	res := struct {
		Success bool
		Errors  map[string]string
	}{Success: true}

	if reg.Validate(false, true) {
		viper.Set("user.name", reg.Name)
		viper.Set("user.email", reg.Email)

		if reg.NewPassword != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(reg.NewPassword), bcrypt.MinCost)
			if err != nil {
				res.Success = false
				errorHandler(w, r, err, http.StatusInternalServerError)
				return
			}
			viper.Set("user.password", string(hash))

			// Forget current session, so user has to login with the new password
			appSession = nil
		}

		viper.WriteConfig()

	} else {
		res.Success = false
		res.Errors = reg.Errors
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func _configUpdateHandler(w http.ResponseWriter, r *http.Request) {
	cfg := &SetupConfig{
		Fqdn:             r.Form.Get("fqdn"),
		Organization:     r.Form.Get("organization"),
		DNS:              r.Form.Get("dns"),
		DomainMode:       r.Form.Get("domain_mode"),
		LockdownDomains:  r.Form.Get("lockdown_domains"),
		WhitelistDomains: r.Form.Get("whitelist_domains"),
		ExtendedTimeout:  (r.Form.Get("extended_timeout") == "true"),
	}

	res := struct {
		Success bool
		Errors  map[string]string
	}{Success: true}

	if cfg.Validate(true) {
		delta := false

		if cfg.Fqdn != viper.GetString("labca.fqdn") {
			delta = true
			viper.Set("labca.fqdn", cfg.Fqdn)
		}

		if cfg.Organization != viper.GetString("labca.organization") {
			delta = true
			viper.Set("labca.organization", cfg.Organization)
		}

		matched, err := regexp.MatchString(":\\d+$", cfg.DNS)
		if err == nil && !matched {
			cfg.DNS += ":53"
		}

		if cfg.DNS != viper.GetString("labca.dns") {
			delta = true
			viper.Set("labca.dns", cfg.DNS)
		}

		domainMode := cfg.DomainMode
		if domainMode != viper.GetString("labca.domain_mode") {
			delta = true
			viper.Set("labca.domain_mode", cfg.DomainMode)
		}

		if domainMode == "lockdown" {
			if cfg.LockdownDomains != viper.GetString("labca.lockdown") {
				delta = true
				viper.Set("labca.lockdown", cfg.LockdownDomains)
			}
		}
		if domainMode == "whitelist" {
			if cfg.WhitelistDomains != viper.GetString("labca.whitelist") {
				delta = true
				viper.Set("labca.whitelist", cfg.WhitelistDomains)
			}
		}

		extendedTimeout := cfg.ExtendedTimeout
		if extendedTimeout != viper.GetBool("labca.extended_timeout") {
			delta = true
			viper.Set("labca.extended_timeout", cfg.ExtendedTimeout)
		}

		if delta {
			viper.WriteConfig()

			err := _applyConfig()
			if err != nil {
				res.Success = false
				res.Errors = cfg.Errors
				res.Errors["ConfigUpdate"] = "Config apply error: '" + err.Error() + "'"
			}
		} else {
			res.Success = false
			res.Errors = cfg.Errors
			res.Errors["ConfigUpdate"] = "Nothing changed!"
		}

	} else {
		res.Success = false
		res.Errors = cfg.Errors
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// EmailConfig stores configuration used for sending out emails
type EmailConfig struct {
	DoEmail   bool
	Server    string
	Port      string
	EmailUser string
	EmailPwd  []byte
	From      string
	Errors    map[string]string
}

// Validate that the email config is valid and complete
func (cfg *EmailConfig) Validate() bool {
	cfg.Errors = make(map[string]string)

	result, err := _encrypt(cfg.EmailPwd)
	if err == nil {
		cfg.EmailPwd = []byte(result)
	} else {
		cfg.Errors["EmailPwd"] = "Could not encrypt this password: " + err.Error()
	}

	if cfg.DoEmail == false {
		return len(cfg.Errors) == 0
	}

	if strings.TrimSpace(cfg.Server) == "" {
		cfg.Errors["Server"] = "Please enter the email server address"
	}

	if strings.TrimSpace(cfg.Port) == "" {
		cfg.Errors["Port"] = "Please enter the email server port number"
	}

	p, err := strconv.Atoi(cfg.Port)
	if err != nil {
		cfg.Errors["Port"] = "Port number must be numeric"
	} else if p <= 0 {
		cfg.Errors["Port"] = "Port number must be positive"
	} else if p > 65535 {
		cfg.Errors["Port"] = "Port number too large"
	}

	if strings.TrimSpace(cfg.EmailUser) == "" {
		cfg.Errors["EmailUser"] = "Please enter the username for authorization to the email server"
	}

	res, err := _decrypt(string(cfg.EmailPwd))
	if err != nil {
		cfg.Errors["EmailPwd"] = "Could not decrypt this password: " + err.Error()
	}
	if strings.TrimSpace(string(res)) == "" {
		cfg.Errors["EmailPwd"] = "Please enter the password for authorization to the email server"
	}

	if strings.TrimSpace(cfg.From) == "" {
		cfg.Errors["From"] = "Please enter the from email address"
	}

	return len(cfg.Errors) == 0
}

func _emailUpdateHandler(w http.ResponseWriter, r *http.Request) {
	cfg := &EmailConfig{
		DoEmail:   (r.Form.Get("do_email") == "true"),
		Server:    r.Form.Get("server"),
		Port:      r.Form.Get("port"),
		EmailUser: r.Form.Get("email_user"),
		EmailPwd:  []byte(r.Form.Get("email_pwd")),
		From:      r.Form.Get("from"),
	}

	res := struct {
		Success bool
		Errors  map[string]string
	}{Success: true}

	if cfg.Validate() {
		delta := false

		if cfg.DoEmail != viper.GetBool("labca.email.enable") {
			delta = true
			viper.Set("labca.email.enable", cfg.DoEmail)
		}

		if cfg.Server != viper.GetString("labca.email.server") {
			delta = true
			viper.Set("labca.email.server", cfg.Server)
		}

		if cfg.Port != viper.GetString("labca.email.port") {
			delta = true
			viper.Set("labca.email.port", cfg.Port)
		}

		if cfg.EmailUser != viper.GetString("labca.email.user") {
			delta = true
			viper.Set("labca.email.user", cfg.EmailUser)
		}

		res1, err1 := _decrypt(string(cfg.EmailPwd))
		if err1 != nil && cfg.DoEmail {
			log.Println("WARNING: could not decrypt given password: " + err1.Error())
		}
		res2, err2 := _decrypt(viper.GetString("labca.email.pass"))
		if err2 != nil && cfg.DoEmail && viper.GetString("labca.email.pass") != "" {
			log.Println("WARNING: could not decrypt stored password: " + err2.Error())
		}
		if string(res1) != string(res2) {
			delta = true
			viper.Set("labca.email.pass", string(cfg.EmailPwd))
		}

		if cfg.From != viper.GetString("labca.email.from") {
			delta = true
			viper.Set("labca.email.from", cfg.From)
		}

		if delta {
			viper.WriteConfig()

			err := _applyConfig()
			if err != nil {
				res.Success = false
				res.Errors = cfg.Errors
				res.Errors["EmailUpdate"] = "Config apply error: '" + err.Error() + "'"
			}
		} else {
			res.Success = false
			res.Errors = cfg.Errors
			res.Errors["EmailUpdate"] = "Nothing changed!"
		}

	} else {
		res.Success = false
		res.Errors = cfg.Errors
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func _emailSendHandler(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Success bool
		Errors  map[string]string
	}{Success: true, Errors: make(map[string]string)}

	recipient := viper.GetString("user.email")
	if !_hostCommand(w, r, "test-email", recipient) {
		res.Success = false
		res.Errors["EmailSend"] = "Failed to send email - see logs"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func _exportHandler(w http.ResponseWriter, r *http.Request) {
	basename := "certificates"
	if r.Form.Get("root") != "true" {
		basename = "issuer"
	}
	if r.Form.Get("issuer") != "true" {
		basename = "root"
	}

	if r.Form.Get("type") == "pfx" {
		w.Header().Set("Content-Type", "application/x-pkcs12")
		w.Header().Set("Content-Disposition", "attachment; filename=labca_"+basename+".pfx")

		var certBase string
		if basename == "root" {
			certBase = "data/root-ca"
		} else {
			certBase = "data/issuer/ca-int"
		}

		cmd := "openssl pkcs12 -export -inkey " + certBase + ".key -in " + certBase + ".pem -passout pass:" + r.Form.Get("export-pwd")

		_sendCmdOutput(w, r, cmd)
	}

	if r.Form.Get("type") == "zip" {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=labca_"+basename+".zip")

		cmd := "zip -j -P " + r.Form.Get("export-pwd") + " - "
		var certBase string
		if r.Form.Get("root") == "true" {
			certBase = "data/root-ca"
			cmd = cmd + certBase + ".key " + certBase + ".pem "
		}
		if r.Form.Get("issuer") == "true" {
			certBase = "data/issuer/ca-int"
			cmd = cmd + certBase + ".key " + certBase + ".pem "
		}

		_sendCmdOutput(w, r, cmd)
	}
}

func _doCmdOutput(w http.ResponseWriter, r *http.Request, cmd string) string {
	parts := strings.Fields(cmd)
	for i := 0; i < len(parts); i++ {
		parts[i] = strings.Replace(parts[i], "\\\\", " ", -1)
	}
	head := parts[0]
	parts = parts[1:]

	out, err := exec.Command(head, parts...).Output()
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ""
	}

	return string(out)
}

func _encrypt(plaintext []byte) (string, error) {
	key := []byte(viper.GetString("keys.enc"))
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, nil)), nil
}

func _decrypt(ciphertext string) ([]byte, error) {
	key := []byte(viper.GetString("keys.enc"))
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	if len(ct) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil)
}

// Result contains data on managed processes
type Result struct {
	Success      bool
	Message      string
	Timestamp    string
	TimestampRel string
	Class        string
}

// ManageComponents sets the additional data to be displayed on the page for the LabCA components
func (res *Result) ManageComponents(w http.ResponseWriter, r *http.Request, action string) {
	components := _parseComponents(getLog(w, r, "components"))
	for i := 0; i < len(components); i++ {
		if (components[i].Name == "NGINX Webserver" && (action == "nginx-reload" || action == "nginx-restart")) ||
			(components[i].Name == "Host Service" && action == "svc-restart") ||
			(components[i].Name == "Boulder (ACME)" && (action == "boulder-start" || action == "boulder-stop" || action == "boulder-restart")) ||
			(components[i].Name == "LabCA Application" && action == "labca-restart") {
			res.Timestamp = components[i].Timestamp
			res.TimestampRel = components[i].TimestampRel
			res.Class = components[i].Class
			break
		}
	}
}

func _checkUpdatesHandler(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Success          bool
		UpdateAvailable  bool
		UpdateChecked    string
		UpdateCheckedRel string
		Versions         []string
		Descriptions     []string
		Errors           map[string]string
	}{Success: true, Errors: make(map[string]string)}

	res.Versions, res.Descriptions = checkUpdates(true)
	res.UpdateAvailable = updateAvailable
	res.UpdateChecked = updateChecked.Format("02-Jan-2006 15:04:05 MST")
	res.UpdateChecked = strings.Replace(res.UpdateChecked, "+0000", "GMT", -1)
	res.UpdateCheckedRel = humanize.RelTime(updateChecked, time.Now(), "", "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func _managePostDispatch(w http.ResponseWriter, r *http.Request, action string) bool {
	if action == "backup-restore" || action == "backup-delete" || action == "backup-now" {
		_backupHandler(w, r)
		return true
	}

	if action == "cert-export" {
		_exportHandler(w, r)
		return true
	}

	if action == "update-account" {
		_accountUpdateHandler(w, r)
		return true
	}

	if action == "update-config" {
		_configUpdateHandler(w, r)
		return true
	}

	if action == "update-email" {
		_emailUpdateHandler(w, r)
		return true
	}

	if action == "send-email" {
		_emailSendHandler(w, r)
		return true
	}

	if action == "version-check" {
		_checkUpdatesHandler(w, r)
		return true
	}

	return false
}

func _managePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return
	}

	action := r.Form.Get("action")
	actionKnown := false
	for _, a := range []string{
		"backup-restore",
		"backup-delete",
		"backup-now",
		"cert-export",
		"nginx-reload",
		"nginx-restart",
		"svc-restart",
		"boulder-start",
		"boulder-stop",
		"boulder-restart",
		"labca-restart",
		"server-restart",
		"server-shutdown",
		"update-account",
		"update-config",
		"update-email",
		"send-email",
		"version-check",
		"version-update",
	} {
		if a == action {
			actionKnown = true
		}
	}
	if !actionKnown {
		errorHandler(w, r, fmt.Errorf("Unknown manage action '%s'", action), http.StatusBadRequest)
		return
	}

	if _managePostDispatch(w, r, action) {
		return
	}

	res := &Result{Success: true}
	if !_hostCommand(w, r, action) {
		res.Success = false
		res.Message = "Command failed - see LabCA log for any details"
	}

	if action != "server-restart" && action != "server-shutdown" && action != "version-update" {
		res.ManageComponents(w, r, action)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func _manageGet(w http.ResponseWriter, r *http.Request) {
	manageData := make(map[string]interface{})
	manageData["RequestBase"] = r.Header.Get("X-Request-Base")

	checkUpdates(false)
	manageData["UpdateAvailable"] = updateAvailable
	manageData["UpdateChecked"] = strings.Replace(updateChecked.Format("02-Jan-2006 15:04:05 MST"), "+0000", "GMT", -1)
	manageData["UpdateCheckedRel"] = humanize.RelTime(updateChecked, time.Now(), "", "")

	components := _parseComponents(getLog(w, r, "components"))
	for i := 0; i < len(components); i++ {
		if components[i].Name == "NGINX Webserver" {
			components[i].LogURL = r.Header.Get("X-Request-Base") + "/logs/weberr"
			components[i].LogTitle = "Web Error Log"

			btn := make(map[string]interface{})
			btn["Class"] = "btn-info"
			btn["Id"] = "nginx-reload"
			btn["Title"] = "Reload web server configuration with minimal impact to the users"
			btn["Label"] = "Reload"
			components[i].Buttons = append(components[i].Buttons, btn)

			btn = make(map[string]interface{})
			btn["Class"] = "btn-warning"
			btn["Id"] = "nginx-restart"
			btn["Title"] = "Restart the web server with some downtime for the users"
			btn["Label"] = "Restart"
			components[i].Buttons = append(components[i].Buttons, btn)
		}

		if components[i].Name == "Host Service" {
			components[i].LogURL = ""
			components[i].LogTitle = ""

			btn := make(map[string]interface{})
			btn["Class"] = "btn-warning"
			btn["Id"] = "svc-restart"
			btn["Title"] = "Restart the host service"
			btn["Label"] = "Restart"
			components[i].Buttons = append(components[i].Buttons, btn)
		}

		if components[i].Name == "Boulder (ACME)" {
			components[i].LogURL = r.Header.Get("X-Request-Base") + "/logs/boulder"
			components[i].LogTitle = "ACME Log"

			btn := make(map[string]interface{})
			cls := "btn-success"
			if components[i].TimestampRel != "stopped" {
				cls = cls + " hidden"
			}
			btn["Class"] = cls
			btn["Id"] = "boulder-start"
			btn["Title"] = "Start the core ACME application"
			btn["Label"] = "Start"
			components[i].Buttons = append(components[i].Buttons, btn)

			btn = make(map[string]interface{})
			cls = "btn-warning"
			if components[i].TimestampRel == "stopped" {
				cls = cls + " hidden"
			}
			btn["Class"] = cls
			btn["Id"] = "boulder-restart"
			btn["Title"] = "Stop and restart the core ACME application"
			btn["Label"] = "Restart"
			components[i].Buttons = append(components[i].Buttons, btn)

			btn = make(map[string]interface{})
			cls = "btn-danger"
			if components[i].TimestampRel == "stopped" {
				cls = cls + " hidden"
			}
			btn["Class"] = cls
			btn["Id"] = "boulder-stop"
			btn["Title"] = "Stop the core ACME application; users can no longer use ACME clients to interact with this instance"
			btn["Label"] = "Stop"
			components[i].Buttons = append(components[i].Buttons, btn)
		}

		if components[i].Name == "LabCA Application" {
			components[i].LogURL = r.Header.Get("X-Request-Base") + "/logs/labca"
			components[i].LogTitle = "LabCA Log"

			btn := make(map[string]interface{})
			btn["Class"] = "btn-warning"
			btn["Id"] = "labca-restart"
			btn["Title"] = "Stop and restart this LabCA admin application"
			btn["Label"] = "Restart"
			components[i].Buttons = append(components[i].Buttons, btn)
		}
	}
	manageData["Components"] = components

	stats := _parseStats(getLog(w, r, "stats"))
	for _, stat := range stats {
		if stat.Name == "System Uptime" {
			manageData["ServerTimestamp"] = stat.Hint
			manageData["ServerTimestampRel"] = stat.Value
			break
		}
	}

	backupFiles := strings.Split(getLog(w, r, "backups"), "\n")
	backupFiles = backupFiles[:len(backupFiles)-1]
	manageData["BackupFiles"] = backupFiles

	manageData["RootDetails"] = _doCmdOutput(w, r, "openssl x509 -noout -text -in data/root-ca.pem")
	manageData["IssuerDetails"] = _doCmdOutput(w, r, "openssl x509 -noout -text -in data/issuer/ca-int.pem")

	manageData["Fqdn"] = viper.GetString("labca.fqdn")
	manageData["Organization"] = viper.GetString("labca.organization")
	manageData["DNS"] = viper.GetString("labca.dns")
	domainMode := viper.GetString("labca.domain_mode")
	manageData["DomainMode"] = domainMode
	if domainMode == "lockdown" {
		manageData["LockdownDomains"] = viper.GetString("labca.lockdown")
	}
	if domainMode == "whitelist" {
		manageData["WhitelistDomains"] = viper.GetString("labca.whitelist")
	}
	manageData["ExtendedTimeout"] = viper.GetBool("labca.extended_timeout")

	manageData["DoEmail"] = viper.GetBool("labca.email.enable")
	manageData["Server"] = viper.GetString("labca.email.server")
	manageData["Port"] = viper.GetInt("labca.email.port")
	manageData["EmailUser"] = viper.GetString("labca.email.user")
	manageData["EmailPwd"] = ""
	if viper.Get("labca.email.pass") != nil {
		pwd := viper.GetString("labca.email.pass")
		result, err := _decrypt(pwd)
		if err == nil {
			manageData["EmailPwd"] = string(result)
		} else {
			log.Printf("WARNING: could not decrypt email password: %s!\n", err.Error())
		}
	}
	manageData["From"] = viper.GetString("labca.email.from")

	manageData["Name"] = viper.GetString("user.name")
	manageData["Email"] = viper.GetString("user.email")

	render(w, r, "manage", manageData)
}

func manageHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		_managePost(w, r)
	} else {
		_manageGet(w, r)
	}
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logType := vars["type"]

	proto := "ws"
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		proto = "wss"
	}

	wsurl := proto + "://" + r.Host + r.Header.Get("X-Request-Base") + "/ws?logType=" + logType

	var name string
	var message string
	var data string

	switch logType {
	case "cert":
		name = "Web Certificate Log"
		message = "Log file for the certificate renewal for this server."
		wsurl = ""
		data = getLog(w, r, logType)
	case "boulder":
		name = "ACME Backend Log"
		message = "Live view on the backend ACME application (Boulder) logs."
	case "audit":
		name = "ACME Audit Log"
		message = "Live view on only the audit messages in the backend ACME application (Boulder) logs."
	case "labca":
		name = "LabCA Log"
		message = "Live view on the logs for this LabCA web application."
	case "web":
		name = "Web Access Log"
		message = "Live view on the NGINX web server access log."
	case "weberr":
		name = "Web Error Log"
		message = "Log file for the NGINX web server error log."
		wsurl = ""
		data = getLog(w, r, logType)
	default:
		errorHandler(w, r, fmt.Errorf("Unknown log type '%s'", logType), http.StatusBadRequest)
		return
	}

	render(w, r, "logs", map[string]interface{}{
		"Name":    name,
		"Message": message,
		"Data":    data,
		"WsUrl":   wsurl,
	})
}

func getLog(w http.ResponseWriter, r *http.Request, logType string) string {
	ip, err := _discoverGateway()
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ""
	}

	conn, err := net.Dial("tcp", ip.String()+":3030")
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ""
	}

	defer conn.Close()

	fmt.Fprintf(conn, "log-"+logType+"\n")
	reader := bufio.NewReader(conn)
	contents, err := ioutil.ReadAll(reader)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ""
	}

	return string(contents)
}

func wsErrorHandler(err error) {
	log.Printf("wsErrorHandler: %v", err)

	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	fmt.Printf("%s:%d, %s\n", frame.File, frame.Line, frame.Function)

	debug.PrintStack()
}

func showLog(ws *websocket.Conn, logType string) {
	ip, err := _discoverGateway()
	if err != nil {
		wsErrorHandler(err)
		return
	}

	conn, err := net.Dial("tcp", ip.String()+":3030")
	if err != nil {
		wsErrorHandler(err)
		return
	}

	defer conn.Close()

	fmt.Fprintf(conn, "log-"+logType+"\n")
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		msg := scanner.Text()
		if logType != "audit" || strings.Index(msg, "[AUDIT]") > -1 {
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				// Probably "websocket: close sent"
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		wsErrorHandler(err)
		return
	}

	return
}

func reader(ws *websocket.Conn) {
	defer ws.Close()
	ws.SetReadLimit(512)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error { ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func writer(ws *websocket.Conn, logType string) {
	pingTicker := time.NewTicker(pingPeriod)
	defer func() {
		pingTicker.Stop()
		ws.Close()
	}()

	go showLog(ws, logType)

	for {
		select {
		case <-pingTicker.C:
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				// Probably "websocket: close sent"
				return
			}
		}
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		if _, ok := err.(websocket.HandshakeError); !ok {
			log.Println(err)
		}
		return
	}

	logType := r.FormValue("logType")

	switch logType {
	case "boulder":
	case "audit":
	case "labca":
	case "web":
	default:
		errorHandler(w, r, fmt.Errorf("Unknown log type '%s'", logType), http.StatusBadRequest)
		return
	}

	go writer(ws, logType)
	reader(ws)
}

func _buildCI(r *http.Request, session *sessions.Session, isRoot bool) *CertificateInfo {
	ci := &CertificateInfo{
		IsRoot:      isRoot,
		CreateType:  "generate",
		CommonName:  "Root CA",
		RequestBase: r.Header.Get("X-Request-Base"),
	}
	if !isRoot {
		ci.CommonName = "CA"
	}
	ci.Initialize()

	if session.Values["ct"] != nil {
		ci.CreateType = session.Values["ct"].(string)
	}
	if session.Values["kt"] != nil {
		ci.KeyType = session.Values["kt"].(string)
	}
	if session.Values["c"] != nil {
		ci.Country = session.Values["c"].(string)
	}
	if session.Values["o"] != nil {
		ci.Organization = session.Values["o"].(string)
	}
	if session.Values["ou"] != nil {
		ci.OrgUnit = session.Values["ou"].(string)
	}
	if session.Values["cn"] != nil {
		ci.CommonName = session.Values["cn"].(string)
		ci.CommonName = strings.Replace(ci.CommonName, "Root", "", -1)
		ci.CommonName = strings.Replace(ci.CommonName, "  ", " ", -1)
	}

	return ci
}

func _certCreate(w http.ResponseWriter, r *http.Request, certBase string, isRoot bool) bool {
	path := "data/"
	if !isRoot {
		path = path + "issuer/"
	}

	if _, err := os.Stat(path + certBase + ".pem"); os.IsNotExist(err) {
		session := getSession(w, r)

		if r.Method == "GET" {
			ci := _buildCI(r, session, isRoot)

			render(w, r, "cert:manage", map[string]interface{}{"CertificateInfo": ci, "Progress": _progress(certBase), "HelpText": _helptext(certBase)})
			return false
		} else if r.Method == "POST" {
			if err := r.ParseMultipartForm(2 * 1024 * 1024); err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return false
			}

			ci := &CertificateInfo{
				IsRoot: r.Form.Get("cert") == "root",
			}
			ci.Initialize()
			ci.IsRoot = r.Form.Get("cert") == "root"
			ci.CreateType = r.Form.Get("createtype")

			if r.Form.Get("keytype") != "" {
				ci.KeyType = r.Form.Get("keytype")
			}
			ci.Country = r.Form.Get("c")
			ci.Organization = r.Form.Get("o")
			ci.OrgUnit = r.Form.Get("ou")
			ci.CommonName = r.Form.Get("cn")

			if ci.CreateType == "import" {
				file, handler, err := r.FormFile("import")
				if err != nil {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return false
				}

				defer file.Close()

				ci.ImportFile = file
				ci.ImportHandler = handler
				ci.ImportPwd = r.Form.Get("import-pwd")
			}

			ci.Key = r.Form.Get("key")
			ci.Passphrase = r.Form.Get("passphrase")
			ci.Certificate = r.Form.Get("certificate")
			ci.RequestBase = r.Header.Get("X-Request-Base")

			if ci.Validate() == false {
				render(w, r, "cert:manage", map[string]interface{}{"CertificateInfo": ci, "Progress": _progress(certBase), "HelpText": _helptext(certBase)})
				return false
			}

			if err := ci.Create(path, certBase); err != nil {
				ci.Errors[strings.Title(ci.CreateType)] = err.Error()
				log.Printf("_certCreate: create failed: %v", err)
				render(w, r, "cert:manage", map[string]interface{}{"CertificateInfo": ci, "Progress": _progress(certBase), "HelpText": _helptext(certBase)})
				return false
			}

			if viper.Get("labca.organization") == nil {
				viper.Set("labca.organization", ci.Organization)
				viper.WriteConfig()
			}

			session.Values["ct"] = ci.CreateType
			session.Values["kt"] = ci.KeyType
			session.Values["c"] = ci.Country
			session.Values["o"] = ci.Organization
			session.Values["ou"] = ci.OrgUnit
			session.Values["cn"] = ci.CommonName
			session.Save(r, w)

			// Fake the method to GET as we need to continue in the setupHandler() function
			r.Method = "GET"
		} else {
			http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusSeeOther)
			return false
		}
	}

	return true
}

func _parseLinuxIPRouteShow(output []byte) (net.IP, error) {
	// Linux '/usr/bin/ip route show' format looks like this:
	// default via 192.168.178.1 dev wlp3s0  metric 303
	// 192.168.178.0/24 dev wlp3s0  proto kernel  scope link  src 192.168.178.76  metric 303
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "default" {
			ip := net.ParseIP(fields[2])
			if ip != nil {
				return ip, nil
			}
		}
	}

	return nil, errors.New("no gateway found")
}

func _discoverGateway() (net.IP, error) {
	if isDev {
		ip := net.ParseIP("127.0.0.1")
		if ip != nil {
			return ip, nil
		}
	}

	routeCmd := exec.Command("ip", "route", "show")
	output, err := routeCmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return _parseLinuxIPRouteShow(output)
}

func _hostCommand(w http.ResponseWriter, r *http.Request, command string, params ...string) bool {
	ip, err := _discoverGateway()
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return false
	}

	conn, err := net.Dial("tcp", ip.String()+":3030")
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return false
	}

	defer conn.Close()

	fmt.Fprintf(conn, command+"\n")
	for _, param := range params {
		fmt.Fprintf(conn, param+"\n")
	}

	reader := bufio.NewReader(conn)
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return false
	}

	if strings.Compare(string(message), "ok\n") == 0 {
		return true
	}

	if len(message) >= 4 {
		tail := message[len(message)-4:]
		if strings.Compare(string(tail), "\nok\n") == 0 {
			msg := message[0 : len(message)-4]
			log.Printf("Message from server: '%s'", msg)
			return true
		}
	}

	log.Printf("ERROR: Message from server: '%s'", message)
	errorHandler(w, r, errors.New(string(message)), http.StatusInternalServerError)
	return false
}

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func _applyConfig() error {
	os.Setenv("PKI_ROOT_CERT_BASE", "data/root-ca")
	os.Setenv("PKI_INT_CERT_BASE", "data/issuer/ca-int")
	os.Setenv("PKI_DEFAULT_O", viper.GetString("labca.organization"))
	os.Setenv("PKI_DNS", viper.GetString("labca.dns"))
	domain := viper.GetString("labca.fqdn")
	os.Setenv("PKI_FQDN", domain)
	pos := strings.Index(domain, ".")
	if pos > -1 {
		pos = pos + 1
		domain = domain[pos:]
	}
	os.Setenv("PKI_DOMAIN", domain)
	os.Setenv("PKI_DOMAIN_MODE", viper.GetString("labca.domain_mode"))
	os.Setenv("PKI_LOCKDOWN_DOMAINS", viper.GetString("labca.lockdown"))
	os.Setenv("PKI_WHITELIST_DOMAINS", viper.GetString("labca.whitelist"))
	if viper.GetBool("labca.extended_timeout") {
		os.Setenv("PKI_EXTENDED_TIMEOUT", "1")
	} else {
		os.Setenv("PKI_EXTENDED_TIMEOUT", "0")
	}
	if viper.GetBool("labca.email.enable") {
		os.Setenv("PKI_EMAIL_SERVER", viper.GetString("labca.email.server"))
		os.Setenv("PKI_EMAIL_PORT", viper.GetString("labca.email.port"))
		os.Setenv("PKI_EMAIL_USER", viper.GetString("labca.email.user"))
		res, err := _decrypt(viper.GetString("labca.email.pass"))
		if err != nil {
			log.Println("WARNING: could not decrypt stored password: " + err.Error())
		}
		os.Setenv("PKI_EMAIL_PASS", string(res))
		os.Setenv("PKI_EMAIL_FROM", viper.GetString("labca.email.from"))
	} else {
		os.Setenv("PKI_EMAIL_SERVER", "localhost")
		os.Setenv("PKI_EMAIL_PORT", "9380")
		os.Setenv("PKI_EMAIL_USER", "cert-master@example.com")
		os.Setenv("PKI_EMAIL_PASS", "password")
		os.Setenv("PKI_EMAIL_FROM", "Expiry bot <test@example.com>")
	}

	_, err := exeCmd("./apply")
	if err != nil {
		fmt.Println("")
	}
	return err
}

func _progress(stage string) int {
	max := 20.0 / 100.0
	curr := 1.0

	if stage == "register" {
		return int(math.Round(curr / max))
	}
	curr += 2.0

	if stage == "setup" {
		return int(math.Round(curr / max))
	}
	curr += 3.0

	if stage == "root-ca" {
		return int(math.Round(curr / max))
	}
	curr += 4.0

	if stage == "ca-int" {
		return int(math.Round(curr / max))
	}
	curr += 3.0

	if stage == "polling" {
		return int(math.Round(curr / max))
	}
	curr += 4.0

	if stage == "wrapup" {
		return int(math.Round(curr / max))
	}
	curr += 3.0

	if stage == "final" {
		return int(math.Round(curr / max))
	}

	return 0
}

func _helptext(stage string) template.HTML {
	if stage == "register" {
		return template.HTML(fmt.Sprint("<p>You need to create an admin account for managing this instance of\n",
			"LabCA. There can only be one admin account, but you can configure all its attributes once the\n",
			"initial setup has completed.</p>"))
	} else if stage == "setup" {
		return template.HTML(fmt.Sprint("<p>The fully qualified domain name (FQDN) is what end users will use\n",
			"to connect to this server. It was provided in the initial setup and is shown here for reference.</p>\n",
			"<p>Please fill in a DNS server (and optionally port, default is ':53') that will be used to lookup\n",
			"the domains for which a certificate is requested.</p>\n",
			"<p>LabCA is primarily intended for use inside an organization where all domains end in the same\n",
			"domain, e.g. '.localdomain'. In lockdown mode only those domains are allowed. In whitelist mode\n",
			"those domains are allowed next to all official, internet accessible domains and in standard\n",
			"mode only the official domains are allowed.</p>"))
	} else if stage == "root-ca" {
		return template.HTML(fmt.Sprint("<p>This is the top level certificate that will sign the issuer\n",
			"certificate(s). You can either generate a fresh Root CA (Certificate Authority) or import an\n",
			"existing one, e.g. a backup from another LabCA instance.</p>\n",
			"<p>If you want to generate a certificate, pick a key type and strength (the higher the number the\n",
			"more secure, ECDSA is more modern than RSA), provide at least a country and organization name,\n",
			"and the common name. It is recommended that the common name contains the word 'Root' as well\n",
			"as your organization name so you can recognize it, and that's why that is automatically filled\n",
			"once you leave the organization field.</p>"))
	} else if stage == "ca-int" {
		return template.HTML(fmt.Sprint("<p>This is what end users will see as the issuing certificate. Again,\n",
			"you can either generate a fresh certificate or import an existing one, as long as it is signed by\n",
			"the Root CA from the previous step.</p>\n",
			"<p>If you want to generate a certificate, by default the same key type and strength is selected as\n",
			"was chosen in the previous step when generating the root (except that the issuer certificate cannot\n",
			"be ECDSA due to a limitation in the Let's Encrypt implementation), but you may choose a different\n",
			"one. By default the common name is the same as the CN for the Root CA, minus the word 'Root'.</p>"))
	} else {
		return template.HTML("")
	}
}

func _setupAdminUser(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == "GET" {
		reg := &User{
			RequestBase: r.Header.Get("X-Request-Base"),
		}
		render(w, r, "register:manage", map[string]interface{}{"User": reg, "IsLogin": true, "Progress": _progress("register"), "HelpText": _helptext("register")})
		return false
	} else if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return false
		}

		reg := &User{
			Name:        r.Form.Get("username"),
			Email:       r.Form.Get("email"),
			Password:    r.Form.Get("password"),
			Confirm:     r.Form.Get("confirm"),
			RequestBase: r.Header.Get("X-Request-Base"),
		}

		if reg.Validate(true, false) == false {
			render(w, r, "register:manage", map[string]interface{}{"User": reg, "IsLogin": true, "Progress": _progress("register"), "HelpText": _helptext("register")})
			return false
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(reg.Password), bcrypt.MinCost)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return false
		}
		viper.Set("user.name", reg.Name)
		viper.Set("user.email", reg.Email)
		viper.Set("user.password", string(hash))
		viper.WriteConfig()

		session := getSession(w, r)
		session.Values["user"] = reg.Name
		session.Save(r, w)

		// Fake the method to GET as we need to continue in the setupHandler() function
		r.Method = "GET"
	} else {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusSeeOther)
		return false
	}

	return true
}

func _setupBaseConfig(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == "GET" {
		domain := viper.GetString("labca.fqdn")
		pos := strings.Index(domain, ".")
		if pos > -1 {
			pos = pos + 1
			domain = domain[pos:]
		}

		cfg := &SetupConfig{
			Fqdn:             viper.GetString("labca.fqdn"),
			DomainMode:       "lockdown",
			LockdownDomains:  domain,
			WhitelistDomains: domain,
			RequestBase:      r.Header.Get("X-Request-Base"),
		}

		render(w, r, "setup:manage", map[string]interface{}{"SetupConfig": cfg, "Progress": _progress("setup"), "HelpText": _helptext("setup")})
		return false
	} else if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return false
		}

		cfg := &SetupConfig{
			Fqdn:             r.Form.Get("fqdn"),
			DNS:              r.Form.Get("dns"),
			DomainMode:       r.Form.Get("domain_mode"),
			LockdownDomains:  r.Form.Get("lockdown_domains"),
			WhitelistDomains: r.Form.Get("whitelist_domains"),
			RequestBase:      r.Header.Get("X-Request-Base"),
		}

		if cfg.Validate(false) == false {
			render(w, r, "setup:manage", map[string]interface{}{"SetupConfig": cfg, "Progress": _progress("setup"), "HelpText": _helptext("setup")})
			return false
		}

		matched, err := regexp.MatchString(":\\d+$", cfg.DNS)
		if err == nil && !matched {
			cfg.DNS += ":53"
		}

		viper.Set("labca.fqdn", cfg.Fqdn)
		viper.Set("labca.dns", cfg.DNS)
		viper.Set("labca.domain_mode", cfg.DomainMode)
		if cfg.DomainMode == "lockdown" {
			viper.Set("labca.lockdown", cfg.LockdownDomains)
		}
		if cfg.DomainMode == "whitelist" {
			viper.Set("labca.whitelist", cfg.WhitelistDomains)
		}
		viper.WriteConfig()

		// Fake the method to GET as we need to continue in the setupHandler() function
		r.Method = "GET"
	} else {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusSeeOther)
		return false
	}

	return true
}

func setupHandler(w http.ResponseWriter, r *http.Request) {
	if viper.GetBool("config.complete") == true {
		render(w, r, "index:manage", map[string]interface{}{"Message": template.HTML("Setup already completed! Go <a href=\"" + r.Header.Get("X-Request-Base") + "/\">home</a>")})
		return
	}

	// 1. Setup admin user
	if viper.Get("user.password") == nil {
		if !_setupAdminUser(w, r) {
			return
		}
	}

	// 2. Setup essential configuration
	if viper.Get("labca.dns") == nil {
		if !_setupBaseConfig(w, r) {
			return
		}
	}

	// 3. Setup root CA certificate
	if !_certCreate(w, r, "root-ca", true) {
		return
	}

	// 4. Setup issuer certificate
	if !_certCreate(w, r, "ca-int", false) {
		return
	}

	// 5. Apply configuration / populate with certificate info
	err := _applyConfig()
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return
	}

	if !viper.GetBool("config.restarted") {
		// 6. Trust the new certs
		if !_hostCommand(w, r, "trust-store") {
			return
		}

		// Don't let the retry mechanism generate new restartSecret!
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			render(w, r, "index", map[string]interface{}{"Message": "Retry OK"})
		} else {
			// 8. Restart application
			restartSecret = randToken()
			http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/wait?restart="+restartSecret, http.StatusFound)
		}
		return
	}

	render(w, r, "wrapup:manage", map[string]interface{}{"Progress": _progress("wrapup"), "HelpText": _helptext("wrapup")})
}

func waitHandler(w http.ResponseWriter, r *http.Request) {
	if viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/", http.StatusFound)
		return
	}

	render(w, r, "polling:manage", map[string]interface{}{"Progress": _progress("polling"), "HelpText": _helptext("polling")})
}

func restartHandler(w http.ResponseWriter, r *http.Request) {
	if viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/", http.StatusFound)
		return
	}

	if strings.Compare(r.URL.Query().Get("token"), restartSecret) != 0 {
		log.Println("WARNING: Restart token ('" + r.URL.Query().Get("token") + "') does not match our secret ('" + restartSecret + "')!")
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	viper.Set("config.restarted", true)
	viper.WriteConfig()

	if !_hostCommand(w, r, "docker-restart") {
		viper.Set("config.restarted", false)
		viper.WriteConfig()
		return
	}
}

func finalHandler(w http.ResponseWriter, r *http.Request) {
	if viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/", http.StatusFound)
		return
	}

	// Don't let the retry mechanism trigger a certificate request and restart!
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		render(w, r, "index", map[string]interface{}{"Message": "Retry OK"})
	} else {
		// 9. Setup our own web certificate
		if !_hostCommand(w, r, "acme-request") {
			http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/logs/cert", http.StatusSeeOther)
			return
		}

		// 10. remove the temporary bit from nginx config
		if !_hostCommand(w, r, "nginx-remove-redirect") {
			return
		}

		// 11. reload nginx
		if !_hostCommand(w, r, "nginx-reload") {
			return
		}

		viper.Set("config.complete", true)
		viper.WriteConfig()

		render(w, r, "final:manage", map[string]interface{}{"RequestBase": r.Header.Get("X-Request-Base"), "Progress": _progress("final"), "HelpText": _helptext("final")})
	}
}

// RangeStructer takes the first argument, which must be a struct, and
// returns the value of each field in a slice. It will return nil
// if there are no arguments or first argument is not a struct
func RangeStructer(args ...interface{}) []interface{} {
	if len(args) == 0 {
		return nil
	}

	v := reflect.ValueOf(args[0])
	if v.Kind() != reflect.Struct {
		return nil
	}

	out := make([]interface{}, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		switch v.Field(i).Kind() {
		case reflect.String:
			if v.Field(i).Type().String() == "template.HTML" {
				out[i] = template.HTML(v.Field(i).String())
			} else {
				out[i] = v.Field(i).String()
			}
		case reflect.Bool:
			out[i] = v.Field(i).Bool()
		default:
			out[i] = v.Field(i)
		}
	}

	return out
}

func accountsHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	Accounts, err := GetAccounts(w, r)
	if err == nil {
		render(w, r, "list:accounts", map[string]interface{}{"List": Accounts})
	}
}

func accountHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		errorHandler(w, r, err, http.StatusBadRequest)
		return
	}

	AccountDetails, err := GetAccount(w, r, id)
	if err == nil {
		render(w, r, "show:accounts", map[string]interface{}{"Details": AccountDetails})
	}
}

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	Orders, err := GetOrders(w, r)
	if err == nil {
		render(w, r, "list:orders", map[string]interface{}{"List": Orders})
	}
}

func orderHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		errorHandler(w, r, err, http.StatusBadRequest)
		return
	}

	OrderDetails, err := GetOrder(w, r, id)
	if err == nil {
		render(w, r, "show:orders", map[string]interface{}{"Details": OrderDetails})
	}
}

func authzHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	Authz, err := GetAuthz(w, r)
	if err == nil {
		render(w, r, "list:authz", map[string]interface{}{"List": Authz})
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	AuthDetails, err := GetAuth(w, r, id)
	if err == nil {
		render(w, r, "show:authz", map[string]interface{}{"Details": AuthDetails})
	}
}

func challengesHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	Challenges, err := GetChallenges(w, r)
	if err == nil {
		render(w, r, "list:challenges", map[string]interface{}{"List": Challenges})
	}
}

func challengeHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		errorHandler(w, r, err, http.StatusBadRequest)
		return
	}

	ChallengeDetails, err := GetChallenge(w, r, id)
	if err == nil {
		render(w, r, "show:challenges", map[string]interface{}{"Details": ChallengeDetails})
	}
}

func certificatesHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	Certificates, err := GetCertificates(w, r)
	if err == nil {
		render(w, r, "list:certificates", map[string]interface{}{"List": Certificates})
	}
}

func certificateHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/setup", http.StatusFound)
		return
	}

	var serial string
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		serial = vars["id"]
	}

	CertificateDetails, err := GetCertificate(w, r, id, serial)
	if err == nil {
		render(w, r, "show:certificates", map[string]interface{}{"Details": CertificateDetails})
	}
}

func certRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if !viper.GetBool("config.complete") {
		errorHandler(w, r, errors.New("Method not allowed at this point"), http.StatusMethodNotAllowed)
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return
		}

		serial := r.Form.Get("serial")
		reason, err := strconv.Atoi(r.Form.Get("reason"))
		if err != nil {
			errorHandler(w, r, err, http.StatusBadRequest)
			return
		}

		if !_hostCommand(w, r, "revoke-cert", serial, strconv.Itoa(reason)) {
			return
		}
	}
}

type navItem struct {
	Name     string
	Icon     string
	Attrs    map[template.HTMLAttr]string
	IsActive bool
	SubMenu  []navItem
}

func _matchPrefix(uri string, prefix string) bool {
	return (uri == prefix || strings.HasPrefix(uri, prefix+"/"))
}

func _acmeNav(active string, uri string, requestBase string) navItem {
	isAcmeActive := _matchPrefix(uri, "/accounts") || _matchPrefix(uri, "/orders") ||
		_matchPrefix(uri, "/authz") || _matchPrefix(uri, "/challenges") ||
		_matchPrefix(uri, "/certificates") || false

	accounts := navItem{
		Name: "Accounts",
		Icon: "fa-list-alt",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/accounts",
			"title": "ACME Accounts",
		},
	}
	orders := navItem{
		Name: "Orders",
		Icon: "fa-tags",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/orders",
			"title": "ACME Orders",
		},
	}
	authz := navItem{
		Name: "Authorizations",
		Icon: "fa-chain",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/authz",
			"title": "ACME Authorizations",
		},
	}
	challenges := navItem{
		Name: "Challenges",
		Icon: "fa-exchange",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/challenges",
			"title": "ACME Challenges",
		},
	}
	certificates := navItem{
		Name: "Certificates",
		Icon: "fa-lock",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/certificates",
			"title": "ACME Certificates",
		},
	}
	acme := navItem{
		Name: "ACME",
		Icon: "fa-sitemap",
		Attrs: map[template.HTMLAttr]string{
			"href":  "#",
			"title": "Automated Certificate Management Environment",
		},
		IsActive: isAcmeActive,
		SubMenu:  []navItem{accounts, certificates, orders, authz, challenges},
	}

	// set active menu class
	switch active {
	case "accounts":
		accounts.Attrs["class"] = "active"
	case "certificates":
		certificates.Attrs["class"] = "active"
	case "orders":
		orders.Attrs["class"] = "active"
	case "authz":
		authz.Attrs["class"] = "active"
	case "challenges":
		challenges.Attrs["class"] = "active"
	}

	return acme
}

func activeNav(active string, uri string, requestBase string) []navItem {
	// create menu items
	home := navItem{
		Name: "Dashboard",
		Icon: "fa-dashboard",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/",
			"title": "Main page with the status of the system",
		},
	}
	acme := _acmeNav(active, uri, requestBase)
	cert := navItem{
		Name: "Web Certificate",
		Icon: "fa-lock",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/logs/cert",
			"title": "Log file for the certificate renewal for this server",
		},
	}
	boulder := navItem{
		Name: "ACME",
		Icon: "fa-search-plus",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/logs/boulder",
			"title": "Live view on the backend ACME application logs",
		},
	}
	audit := navItem{
		Name: "ACME Audit Log",
		Icon: "fa-paw",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/logs/audit",
			"title": "Live view on only the audit messages in the backend ACME application logs",
		},
	}
	labca := navItem{
		Name: "LabCA",
		Icon: "fa-edit",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/logs/labca",
			"title": "Live view on the logs for this LabCA web application",
		},
	}
	web := navItem{
		Name: "Web Access",
		Icon: "fa-globe",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/logs/web",
			"title": "Live view on the NGINX web server access log",
		},
	}
	weberr := navItem{
		Name: "Web Error",
		Icon: "fa-times",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/logs/weberr",
			"title": "Log file for the NGINX web server error log",
		},
	}
	logs := navItem{
		Name: "Logs",
		Icon: "fa-files-o",
		Attrs: map[template.HTMLAttr]string{
			"href":  "#",
			"title": "Log Files",
		},
		IsActive: strings.HasPrefix(uri, "/logs/"),
		SubMenu:  []navItem{cert, boulder, audit, labca, web, weberr},
	}
	manage := navItem{
		Name: "Manage",
		Icon: "fa-wrench",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/manage",
			"title": "Manage the system",
		},
	}
	about := navItem{
		Name: "About",
		Icon: "fa-comments",
		Attrs: map[template.HTMLAttr]string{
			"href":  requestBase + "/about",
			"title": "About LabCA",
		},
	}
	public := navItem{
		Name: "Public Area",
		Icon: "fa-home",
		Attrs: map[template.HTMLAttr]string{
			"href":  "http://" + viper.GetString("labca.fqdn"),
			"title": "The non-Admin pages of this LabCA instance",
		},
	}

	// set active menu class
	switch active {
	case "about":
		about.Attrs["class"] = "active"
	case "index":
		home.Attrs["class"] = "active"
	case "manage":
		manage.Attrs["class"] = "active"
	}

	return []navItem{home, acme, logs, manage, about, public}
}

func render(w http.ResponseWriter, r *http.Request, view string, data map[string]interface{}) {
	viewSlice := strings.Split(view, ":")
	menu := viewSlice[0]
	if len(viewSlice) > 1 {
		menu = viewSlice[1]
	}
	data["Menu"] = activeNav(menu, r.RequestURI, r.Header.Get("X-Request-Base"))

	if version != "" {
		data["Version"] = version
	}

	b, err := tmpls.Render("base.tmpl", "views/"+viewSlice[0]+".tmpl", data)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	errorHandler(w, r, fmt.Errorf("NotFoundHandler for: %s %s", r.Method, r.URL), http.StatusNotFound)
}

func authorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method + " " + r.RequestURI)

		if r.RequestURI == "/login" || strings.Contains(r.RequestURI, "/static/") {
			next.ServeHTTP(w, r)
		} else {
			session := getSession(w, r)
			if session.Values["user"] != nil || (r.RequestURI == "/setup" && viper.Get("user.password") == nil) {
				next.ServeHTTP(w, r)
			} else {
				session.Values["bounce"] = r.RequestURI
				session.Save(r, w)
				http.Redirect(w, r, r.Header.Get("X-Request-Base")+"/login", http.StatusFound)
			}
		}
	})
}

func init() {
	if os.Getenv("DEVELOPMENT") != "" {
		isDev = true
	}

	var err error
	tmpls, err = templates.New().ParseDir("./templates", "templates/")
	if err != nil {
		panic(fmt.Errorf("fatal error templates: '%s'", err))
	}
	tmpls.AddFunc("rangeStruct", RangeStructer)

	viper.SetConfigName("config")
	viper.AddConfigPath("data")
	viper.SetDefault("config.complete", false)
	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("fatal error config file: '%s'", err))
	}

	if viper.Get("keys.auth") == nil {
		key := securecookie.GenerateRandomKey(32)
		if key == nil {
			panic(fmt.Errorf("fatal error random key"))
		}
		viper.Set("keys.auth", key)
		viper.WriteConfig()
	}
	if viper.Get("keys.enc") == nil {
		key := securecookie.GenerateRandomKey(32)
		if key == nil {
			panic(fmt.Errorf("fatal error random key"))
		}
		viper.Set("keys.enc", key)
		viper.WriteConfig()
	}

	if viper.Get("server.addr") == nil {
		viper.Set("server.addr", "0.0.0.0")
		viper.WriteConfig()
	}

	if viper.Get("server.port") == nil {
		viper.Set("server.port", 3000)
		viper.WriteConfig()
	}

	if viper.Get("server.session.maxage") == nil {
		viper.Set("server.session.maxage", 3600) // 1 hour
		viper.WriteConfig()
	}

	if viper.Get("db.conn") == nil {
		viper.Set("db.type", "mysql")
		viper.Set("db.conn", "root@tcp(boulder-mysql:3306)/boulder_sa_integration")
		viper.WriteConfig()
	}
	dbConn = viper.GetString("db.conn")
	dbType = viper.GetString("db.type")

	version = viper.GetString("version")

	updateAvailable = false
}

func main() {
	tmpls.Parse()

	sessionStore = sessions.NewCookieStore([]byte(viper.GetString("keys.auth")), []byte(viper.GetString("keys.enc")))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   viper.GetInt("server.session.maxage") * 1,
		HttpOnly: true,
	}

	r := mux.NewRouter()
	r.HandleFunc("/", rootHandler).Methods("GET")
	r.HandleFunc("/about", aboutHandler).Methods("GET")
	r.HandleFunc("/manage", manageHandler).Methods("GET", "POST")
	r.HandleFunc("/final", finalHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.HandleFunc("/logs/{type}", logsHandler).Methods("GET")
	r.HandleFunc("/restart", restartHandler).Methods("GET")
	r.HandleFunc("/setup", setupHandler).Methods("GET", "POST")
	r.HandleFunc("/wait", waitHandler).Methods("GET")
	r.HandleFunc("/ws", wsHandler).Methods("GET")

	r.HandleFunc("/accounts", accountsHandler).Methods("GET")
	r.HandleFunc("/accounts/{id}", accountHandler).Methods("GET")
	r.HandleFunc("/orders", ordersHandler).Methods("GET")
	r.HandleFunc("/orders/{id}", orderHandler).Methods("GET")
	r.HandleFunc("/authz", authzHandler).Methods("GET")
	r.HandleFunc("/authz/{id}", authHandler).Methods("GET")
	r.HandleFunc("/challenges", challengesHandler).Methods("GET")
	r.HandleFunc("/challenges/{id}", challengeHandler).Methods("GET")
	r.HandleFunc("/certificates", certificatesHandler).Methods("GET")
	r.HandleFunc("/certificates/{id}", certificateHandler).Methods("GET")
	r.HandleFunc("/certificates/{id}", certRevokeHandler).Methods("POST")

	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)
	if isDev {
		r.PathPrefix("/accounts/static/").Handler(http.StripPrefix("/accounts/static/", http.FileServer(http.Dir("../www"))))
		r.PathPrefix("/authz/static/").Handler(http.StripPrefix("/authz/static/", http.FileServer(http.Dir("../www"))))
		r.PathPrefix("/challenges/static/").Handler(http.StripPrefix("/challenges/static/", http.FileServer(http.Dir("../www"))))
		r.PathPrefix("/certificates/static/").Handler(http.StripPrefix("/certificates/static/", http.FileServer(http.Dir("../www"))))
		r.PathPrefix("/orders/static/").Handler(http.StripPrefix("/orders/static/", http.FileServer(http.Dir("../www"))))
		r.PathPrefix("/logs/static/").Handler(http.StripPrefix("/logs/static/", http.FileServer(http.Dir("../www"))))
		r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("../www"))))
	}
	r.Use(authorized)

	log.Printf("Listening on %s:%d...\n", viper.GetString("server.addr"), viper.GetInt("server.port"))
	srv := &http.Server{
		Handler:      r,
		Addr:         viper.GetString("server.addr") + ":" + viper.GetString("server.port"),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
