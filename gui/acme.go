package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/spf13/viper"
	"go.step.sm/crypto/jose"
)

// ListData is a generic struct for storing lists of items with variable number of columns
type ListData struct {
	Title      string
	TableClass string
	Header     []template.HTML
	Rows       [][]any
}

// NameValue is a pair of a name and a value of any type
type NameValue struct {
	Name  string
	Value any
}

// A generic struct for storing a single item plus any lists of related items
type ShowData struct {
	Title      string
	TableClass string
	Rows       []NameValue
	Extra      []template.HTML
	Relateds   []ListData
}

// boulderAccount represents an ACME account in boulder
type boulderAccount struct {
	ID        string
	Status    string
	Contact   string
	Agreement string
	InitialIP net.IP
	CreatedAt string
}

// stepcaAccount represents an ACME account in step-ca, where the struct is called dbAccount
type stepcaAccount struct {
	ID            string           `json:"id"`
	Key           *jose.JSONWebKey `json:"key"`
	Contact       []string         `json:"contact,omitempty"`
	Status        acme.Status      `json:"status"`
	CreatedAt     time.Time        `json:"createdAt"`
	DeactivatedAt time.Time        `json:"deactivatedAt"`
}

// Helper method for transforming any list (strings, ints, ...) into a list of generic values
func toAnyList[T any](input []T) []any {
	list := make([]any, len(input))
	for i, v := range input {
		list[i] = v
	}
	return list
}

// GetAccounts returns the list of ACME accounts
func GetAccounts(w http.ResponseWriter, r *http.Request) (ListData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ListData{}, err
	}

	defer db.Close()

	Accounts := ListData{
		Title:      "Accounts",
		TableClass: "accounts_list",
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		Accounts.Header = []template.HTML{"ID", "Status", "Contact", "Created"}
		Accounts.TableClass += " backend_stepca"

		rows, err = db.Query("SELECT nvalue FROM acme_accounts")
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			account := stepcaAccount{}
			err = json.Unmarshal(row, &account)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			acct := make([]string, 0)
			acct = append(acct, account.ID)
			acct = append(acct, string(account.Status))
			acct = append(acct, strings.Join(account.Contact, ", "))
			acct = append(acct, account.CreatedAt.String())

			Accounts.Rows = append(Accounts.Rows, toAnyList(acct))
		}
	} else {
		Accounts.Header = []template.HTML{"ID", "Status", "Contact", "Agreement", "Initial IP", "Created"}

		rows, err = db.Query("SELECT id, status, contact, agreement, initialIP, createdAt FROM registrations")

		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			account := boulderAccount{}
			err = rows.Scan(&account.ID, &account.Status, &account.Contact, &account.Agreement, &account.InitialIP, &account.CreatedAt)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			Accounts.Rows = append(Accounts.Rows, RangeStructer(account))
		}
	}

	return Accounts, nil
}

// boulderOrder represents an ACME order in boulder
type boulderOrder struct {
	ID             string
	RegistrationID string
	CertSerial     string
	RequestedName  string
	BeganProc      bool
	Created        string
	Expires        string
}

// stepcaOrder represents an ACME order in step-ca, where the struct is called dbOrder
type stepcaOrder struct {
	ID               string            `json:"id"`
	AccountID        string            `json:"accountID"`
	ProvisionerID    string            `json:"provisionerID"`
	Identifiers      []acme.Identifier `json:"identifiers"`
	AuthorizationIDs []string          `json:"authorizationIDs"`
	Status           acme.Status       `json:"status"`
	NotBefore        time.Time         `json:"notBefore,omitempty"`
	NotAfter         time.Time         `json:"notAfter,omitempty"`
	CreatedAt        time.Time         `json:"createdAt"`
	ExpiresAt        time.Time         `json:"expiresAt,omitempty"`
	CertificateID    string            `json:"certificate,omitempty"`
	Error            *acme.Error       `json:"error,omitempty"`
}

// stepcaRevoked represents revoked x509 certificates in step-ca
type stepcaRevoked struct {
	Serial        string    `json:"serial"`
	ProvisionerID string    `json:"provisionerID"`
	ReasonCode    int       `json:"reasonCode"`
	Reason        string    `json:"reason"`
	RevokedAt     time.Time `json:"revokedAt"`
	TokenID       string    `json:"tokenID"`
	MTLS          bool      `json:"mtls"`
	ACME          bool      `json:"acme"`
}

// Get all revoked certificate details from the database in a map of serial numbers
func stepcaGetRevokeds(db *sql.DB) (map[string]stepcaRevoked, error) {
	revokeds := map[string]stepcaRevoked{}
	rows, err := db.Query("SELECT nvalue FROM revoked_x509_certs")
	if err != nil {
		return map[string]stepcaRevoked{}, err
	}

	for rows.Next() {
		row := []byte{}
		err = rows.Scan(&row)
		if err != nil {
			return map[string]stepcaRevoked{}, err
		}

		revoked := stepcaRevoked{}
		err = json.Unmarshal(row, &revoked)
		if err != nil {
			return map[string]stepcaRevoked{}, err
		}

		revokeds[revoked.Serial] = revoked
	}

	return revokeds, nil
}

// stepcaProvisioner contains info about the provisioner that issued this certificate in step-ca
type stepcaProvisioner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// stepcaCertsData contains some extra info about certificates in step-ca
type stepcaCertsData struct {
	Provisioner stepcaProvisioner `json:"provisioner"`
}

// Get additional info on certificates from the database in a map of serial numbers
func stepcaCertsDatas(db *sql.DB) (map[string]stepcaCertsData, error) {
	certsdatas := map[string]stepcaCertsData{}
	rows, err := db.Query("SELECT nkey, nvalue FROM x509_certs_data")
	if err != nil {
		return map[string]stepcaCertsData{}, err
	}

	for rows.Next() {
		row := []byte{}
		serial := ""
		err = rows.Scan(&serial, &row)
		if err != nil {
			return map[string]stepcaCertsData{}, err
		}

		certsdata := stepcaCertsData{}
		err = json.Unmarshal(row, &certsdata)
		if err != nil {
			return map[string]stepcaCertsData{}, err
		}

		certsdatas[serial] = certsdata
	}

	return certsdatas, nil
}

// GetAccount returns a specific account
func GetAccount(w http.ResponseWriter, r *http.Request, id string) (ShowData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ShowData{}, err
	}

	defer db.Close()

	AccountDetails := ShowData{
		Title:      "Account",
		TableClass: "account_show",
	}

	Certificates, err := GetCertificates(w, r, id)
	if err == nil {
		AccountDetails.Relateds = append(AccountDetails.Relateds, Certificates)
	}

	Orders, err := GetOrders(w, r, id)
	if err == nil {
		AccountDetails.Relateds = append(AccountDetails.Relateds, Orders)
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		rows, err = db.Query("SELECT nvalue FROM acme_accounts where nkey=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			account := stepcaAccount{}
			err = json.Unmarshal(row, &account)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"ID", account.ID})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Status", string(account.Status)})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Key ID", account.Key.KeyID})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Key Algorithm", account.Key.Algorithm})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Contacts", strings.Join(account.Contact, ", ")})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Created At", account.CreatedAt.String()})
			if account.DeactivatedAt.IsZero() {
				AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Deactivated At", ""})
			} else {
				AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Deactivated At", account.DeactivatedAt.String()})
			}
		}
	} else {
		rows, err = db.Query("SELECT id, status, contact, agreement, initialIP, createdAt FROM registrations WHERE id=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			account := boulderAccount{}
			err = rows.Scan(&account.ID, &account.Status, &account.Contact, &account.Agreement, &account.InitialIP, &account.CreatedAt)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"ID", account.ID})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Status", account.Status})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Contact", account.Contact})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Agreement", account.Agreement})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Initial IP", account.InitialIP.String()})
			AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Created At", account.CreatedAt})
		}
	}

	return AccountDetails, nil
}

// GetOrders returns the list of orders
func GetOrders(w http.ResponseWriter, r *http.Request, forAccount string) (ListData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ListData{}, err
	}

	defer db.Close()

	Orders := ListData{
		Title:      "Orders",
		TableClass: "orders_list",
		Header:     []template.HTML{"ID", "Account ID", "Certificate Serial", "Requested Name", "Began Processing?", "Created", "Expires"},
	}
	if forAccount != "" {
		Orders.TableClass = "rel_orders_list"
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		Orders.Header = []template.HTML{"ID", "Account ID", "Certificate ID", "Requested Name", "Created", "Expires"}
		Orders.TableClass += " backend_stepca"

		rows, err = db.Query("SELECT nvalue FROM acme_orders")
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			order := stepcaOrder{}
			err = json.Unmarshal(row, &order)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			if forAccount == "" || order.AccountID == forAccount {
				idns := []string{}
				for _, idn := range order.Identifiers {
					idns = append(idns, string(idn.Type)+":"+idn.Value)
				}

				row := make([]string, 0)
				row = append(row, order.ID)
				row = append(row, order.AccountID)
				row = append(row, order.CertificateID)
				row = append(row, strings.Join(idns, ", "))
				row = append(row, order.CreatedAt.String())
				row = append(row, order.ExpiresAt.String())

				Orders.Rows = append(Orders.Rows, toAnyList(row))
			}
		}
	} else {
		if forAccount == "" {
			rows, err = db.Query("SELECT o.id, o.registrationID, o.certificateSerial, n.reversedName, o.beganProcessing, o.created, o.expires FROM orders o JOIN requestedNames n ON n.orderID = o.id")
		} else {
			rows, err = db.Query("SELECT o.id, o.registrationID, o.certificateSerial, n.reversedName, o.beganProcessing, o.created, o.expires FROM orders o JOIN requestedNames n ON n.orderID = o.id WHERE o.registrationID=?", forAccount)
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			order := boulderOrder{}
			err = rows.Scan(&order.ID, &order.RegistrationID, &order.CertSerial, &order.RequestedName, &order.BeganProc, &order.Created, &order.Expires)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}
			order.RequestedName = boulderReverseName(order.RequestedName)
			Orders.Rows = append(Orders.Rows, RangeStructer(order))

		}
	}

	return Orders, nil
}

// bolderAuth contains the data representing an ACME authorization in boulder
type bolderAuth struct {
	ID             string
	Identifier     string
	RegistrationID string
	Status         string
	Expires        string
}

// stepcaAuthz contains the data representing an ACME authorization in step-ca, where the struct is called dbAuthz
type stepcaAuthz struct {
	ID           string          `json:"id"`
	AccountID    string          `json:"accountID"`
	Identifier   acme.Identifier `json:"identifier"`
	Status       acme.Status     `json:"status"`
	Token        string          `json:"token"`
	ChallengeIDs []string        `json:"challengeIDs"`
	Wildcard     bool            `json:"wildcard"`
	CreatedAt    time.Time       `json:"createdAt"`
	ExpiresAt    time.Time       `json:"expiresAt"`
	Error        *acme.Error     `json:"error"`
}

// Helper method from sa/model.go (boulder)
var uintToStatus = map[int]string{
	0: "pending",
	1: "valid",
	2: "invalid",
	3: "deactivated",
	4: "revoked",
}

// Check if a table with the given name exists in the database
func tableExists(db *sql.DB, tableName string) bool {
	rows, _ := db.Query("SHOW TABLES LIKE '" + tableName + "'")
	return rows.Next()
}

// Check if a given column name exists in the given table
func columnExists(db *sql.DB, tableName, columnName string) bool {
	rows, _ := db.Query("SHOW COLUMNS FROM `" + tableName + "` LIKE '" + columnName + "'")
	return rows.Next()
}

// GetOrder returns an order with the given id
func GetOrder(w http.ResponseWriter, r *http.Request, id string) (ShowData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ShowData{}, err
	}

	defer db.Close()

	OrderDetails := ShowData{
		Title:      "Order",
		TableClass: "order_show",
	}

	var stepcaAuthzIDs []string

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		rows, err = db.Query("SELECT nvalue FROM acme_orders WHERE nkey=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			order := stepcaOrder{}
			err = json.Unmarshal(row, &order)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			stepcaAuthzIDs = order.AuthorizationIDs

			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"ID", order.ID})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Status", string(order.Status)})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Provisioner", order.ProvisionerID})
			idns := []string{}
			for _, idn := range order.Identifiers {
				idns = append(idns, string(idn.Type)+":"+idn.Value)
			}
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Identifiers", strings.Join(idns, ", ")})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Certificate", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/certificates/" + order.CertificateID + "\">" + order.CertificateID + "</a>")})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Created", order.CreatedAt.String()})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Expires", order.ExpiresAt.String()})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Not Before", order.NotBefore.String()})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Not After", order.NotAfter.String()})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + order.AccountID + "\">" + order.AccountID + "</a>")})
		}
	} else {
		rows, err = db.Query("SELECT o.id, o.registrationID, o.certificateSerial, n.reversedName, o.beganProcessing, o.created, o.expires FROM orders o JOIN requestedNames n ON n.orderID = o.id WHERE o.id=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			order := boulderOrder{}
			err = rows.Scan(&order.ID, &order.RegistrationID, &order.CertSerial, &order.RequestedName, &order.BeganProc, &order.Created, &order.Expires)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"ID", order.ID})
			v := "false"
			if order.BeganProc {
				v = "true"
			}
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Began Processing?", v})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Certificate", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/certificates/" + order.CertSerial + "\">" + order.CertSerial + "</a>")})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Requested Name", boulderReverseName(order.RequestedName)})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Created", order.Created})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Expires", order.Expires})
			OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + order.RegistrationID + "\">" + order.RegistrationID + "</a>")})
		}
	}

	Authzs, err := GetAuthzs(w, r, id, stepcaAuthzIDs)
	if err == nil {
		OrderDetails.Relateds = append(OrderDetails.Relateds, Authzs)
	}

	return OrderDetails, nil
}

// GetAuthzs returns the list of authorizations
func GetAuthzs(w http.ResponseWriter, r *http.Request, forOrder string, inList []string) (ListData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ListData{}, err
	}

	defer db.Close()

	Authz := ListData{
		Title:      "Authorizations",
		TableClass: "authz_list",
		Header:     []template.HTML{"ID", "Identifier", "Account ID", "Status", "Expires"},
	}

	if forOrder != "" || len(inList) > 0 {
		Authz.TableClass = "rel_authz_list"
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		Authz.TableClass += " backend_stepca"

		if len(inList) > 0 {
			var query string
			var args []interface{}
			query, args, err = sqlx.In("SELECT nvalue FROM acme_authzs WHERE nkey IN (?)", inList)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}
			rows, err = db.Query(query, args...)
		} else {
			rows, err = db.Query("SELECT nvalue FROM acme_authzs")
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			authz := stepcaAuthz{}
			err = json.Unmarshal(row, &authz)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			auth := make([]string, 0)
			auth = append(auth, authz.ID)
			auth = append(auth, string(authz.Identifier.Type)+":"+authz.Identifier.Value)
			auth = append(auth, authz.AccountID)
			auth = append(auth, string(authz.Status))
			auth = append(auth, authz.ExpiresAt.String())

			Authz.Rows = append(Authz.Rows, toAnyList(auth))
		}
	} else {
		query := ""
		if tableExists(db, "authz") {
			ident := "identifier"
			if columnExists(db, "authz", "identifierValue") {
				ident = "identifierValue"
			}
			query = "SELECT id, " + ident + ", registrationID, status, expires FROM authz"

			if forOrder != "" {
				query += " WHERE id IN (SELECT authzID FROM orderToAuthz WHERE orderID=?)"
			}
		}
		if tableExists(db, "authz2") {
			if query != "" {
				query = query + " UNION "
			}
			query = query + "SELECT id, identifierValue, registrationID, status, expires FROM authz2"

			if forOrder != "" {
				query += " WHERE id IN (SELECT authzID FROM orderToAuthz2 WHERE orderID=?)"
			}
		}

		if forOrder != "" {
			if tableExists(db, "authz") && tableExists(db, "authz2") {
				rows, err = db.Query(query, forOrder, forOrder)
			} else {
				rows, err = db.Query(query, forOrder)
			}
		} else {
			rows, err = db.Query(query)
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			authz := bolderAuth{}
			err = rows.Scan(&authz.ID, &authz.Identifier, &authz.RegistrationID, &authz.Status, &authz.Expires)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}
			if s, err := strconv.Atoi(authz.Status); err == nil {
				authz.Status = uintToStatus[s]
			}
			Authz.Rows = append(Authz.Rows, RangeStructer(authz))
		}
	}

	return Authz, nil
}

// boulderChallenge contains the data representing an ACME challenge in boulder
type boulderChallenge struct {
	ID        string
	AuthID    string
	Type      string
	Status    string
	Validated string
	Token     string
}

// stepcaChallenge contains the data representing an ACME challenge in step-ca, where the struct is called dbChallenge
type stepcaChallenge struct {
	ID          string             `json:"id"`
	AccountID   string             `json:"accountID"`
	Type        acme.ChallengeType `json:"type"`
	Status      acme.Status        `json:"status"`
	Token       string             `json:"token"`
	Value       string             `json:"value"`
	ValidatedAt string             `json:"validatedAt"`
	CreatedAt   time.Time          `json:"createdAt"`
	Error       *acme.Error        `json:"error"`
}

// GetAuthz returns an auth with the given id
func GetAuthz(w http.ResponseWriter, r *http.Request, id string) (ShowData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ShowData{}, err
	}

	defer db.Close()

	AuthDetails := ShowData{
		Title:      "Authorization",
		TableClass: "auth_show",
	}

	var challIDs []string

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		rows, err = db.Query("SELECT nvalue FROM acme_authzs WHERE nkey=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			row := []byte{}
			dbauthz := stepcaAuthz{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			err = json.Unmarshal(row, &dbauthz)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			challIDs = dbauthz.ChallengeIDs

			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"ID", dbauthz.ID})
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Identifier", string(dbauthz.Identifier.Type) + ":" + dbauthz.Identifier.Value})
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Status", string(dbauthz.Status)})
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Token", string(dbauthz.Token)})
			v := "false"
			if dbauthz.Wildcard {
				v = "true"
			}
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Wildcard?", v})
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Created At", dbauthz.CreatedAt.String()})
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Expires At", dbauthz.ExpiresAt.String()})

			Link := NameValue{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + dbauthz.AccountID + "\">" + dbauthz.AccountID + "</a>")}
			AuthDetails.Rows = append(AuthDetails.Rows, Link)
		}
	} else {
		query := ""
		if tableExists(db, "authz") {
			if columnExists(db, "authz", "identifierValue") {
				query = "SELECT id, identifierValue, registrationID, status, expires, validationError, validationRecord FROM authz WHERE id IN (SELECT authzID FROM orderToAuthz WHERE id=?)"
			} else {
				query = "SELECT id, identifier, registrationID, status, expires, '', '' FROM authz WHERE id IN (SELECT authzID FROM orderToAuthz WHERE id=?)"
			}
		}
		if tableExists(db, "authz2") {
			if query != "" {
				query = query + " UNION "
			}
			query = query + "SELECT id, identifierValue, registrationID, status, expires, validationError, validationRecord FROM authz2 WHERE id IN (SELECT authzID FROM orderToAuthz2 WHERE id=?)"
		}
		if tableExists(db, "authz") && tableExists(db, "authz2") {
			rows, err = db.Query(query, id, id)
		} else {
			rows, err = db.Query(query, id)
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			row := bolderAuth{}
			validationError := sql.NullString{}
			validationRecord := sql.NullString{}
			err = rows.Scan(&row.ID, &row.Identifier, &row.RegistrationID, &row.Status, &row.Expires, &validationError, &validationRecord)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"ID", row.ID})
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Identifier", row.Identifier})
			if s, err := strconv.Atoi(row.Status); err == nil {
				row.Status = uintToStatus[s]
			}
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Status", row.Status})
			AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Expires", row.Expires})
			if validationError.Valid && validationError.String != "" {
				AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Validation Error", validationError.String})
			}
			if validationRecord.Valid && validationRecord.String != "" {
				AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Validation Record", validationRecord.String})
			}

			Link := NameValue{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + row.RegistrationID + "\">" + row.RegistrationID + "</a>")}
			AuthDetails.Rows = append(AuthDetails.Rows, Link)
		}
	}

	Challenges, err := GetChallenges(w, r, id, challIDs)
	if err == nil {
		AuthDetails.Relateds = append(AuthDetails.Relateds, Challenges)
	}

	return AuthDetails, nil
}

// GetChallenges returns the list of challenges
func GetChallenges(w http.ResponseWriter, r *http.Request, forAuthz string, inList []string) (ListData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ListData{}, err
	}

	defer db.Close()

	Challenges := ListData{
		Title:      "Challenges",
		TableClass: "challenges_list",
		Header:     []template.HTML{"ID", "Authorization ID", "Type", "Status", "Validated", "Token"},
	}

	if forAuthz != "" || len(inList) > 0 {
		Challenges.TableClass = "rel_challenges_list"
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		Challenges.Header = []template.HTML{"ID", "Authorization ID", "Type", "Status", "Created", "Validated"}
		Challenges.TableClass += " backend_stepca"

		arows, err := db.Query("SELECT nvalue FROM acme_authzs")
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		authzs := map[string]string{}
		for arows.Next() {
			row := []byte{}
			err = arows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			authz := stepcaAuthz{}
			err = json.Unmarshal(row, &authz)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			for i := range authz.ChallengeIDs {
				authzs[authz.ChallengeIDs[i]] = authz.ID
			}
		}

		if len(inList) > 0 {
			var query string
			var args []interface{}
			query, args, err = sqlx.In("SELECT nvalue FROM acme_challenges WHERE nkey IN (?)", inList)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			rows, err = db.Query(query, args...)
		} else {
			rows, err = db.Query("SELECT nvalue FROM acme_challenges")
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			challenge := stepcaChallenge{}
			err = json.Unmarshal(row, &challenge)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			chall := make([]string, 0)
			chall = append(chall, challenge.ID)
			chall = append(chall, authzs[challenge.ID])
			chall = append(chall, string(challenge.Type))
			chall = append(chall, string(challenge.Status))
			chall = append(chall, challenge.CreatedAt.String())
			chall = append(chall, challenge.ValidatedAt)

			Challenges.Rows = append(Challenges.Rows, toAnyList(chall))
		}
	} else {
		if forAuthz == "" {
			rows, err = db.Query("SELECT id, authorizationID, type, status, validated, token FROM challenges")
		} else {
			rows, err = db.Query("SELECT id, authorizationID, type, status, validated, token FROM challenges WHERE authorizationID=?", forAuthz)
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			challenge := boulderChallenge{}
			err = rows.Scan(&challenge.ID, &challenge.AuthID, &challenge.Type, &challenge.Status, &challenge.Validated, &challenge.Token)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}
			Challenges.Rows = append(Challenges.Rows, RangeStructer(challenge))
		}
	}

	return Challenges, nil
}

// GetChallenge returns a challenge with the given id
func GetChallenge(w http.ResponseWriter, r *http.Request, id string) (ShowData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ShowData{}, err
	}

	defer db.Close()

	ChallengeDetails := ShowData{
		Title:      "Challenge",
		TableClass: "challenge_show",
		Rows:       []NameValue{},
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		rows, err = db.Query("SELECT nvalue FROM acme_challenges where nkey=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			challenge := stepcaChallenge{}
			err = json.Unmarshal(row, &challenge)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"ID", challenge.ID})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Type", string(challenge.Type)})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Status", string(challenge.Status)})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Created At", challenge.CreatedAt.String()})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Validated At", challenge.ValidatedAt})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Token", challenge.Token})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Value", challenge.Value})

			authzID := ""
			arows, err := db.Query("SELECT nvalue FROM acme_authzs")
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			for arows.Next() {
				row := []byte{}
				err = arows.Scan(&row)
				if err != nil {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return ShowData{}, err
				}

				authz := stepcaAuthz{}
				err = json.Unmarshal(row, &authz)
				if err != nil {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return ShowData{}, err
				}

				for i := range authz.ChallengeIDs {
					if authz.ChallengeIDs[i] == challenge.ID {
						authzID = authz.ID
						break
					}
				}

				if authzID != "" {
					break
				}
			}

			if authzID != "" {
				Link := NameValue{"Authorization", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/authz/" + authzID + "\">" + authzID + "</a>")}
				ChallengeDetails.Rows = append(ChallengeDetails.Rows, Link)
			}
		}
	} else {
		rows, err := db.Query("SELECT id, authorizationID, type, status, validated, token FROM challenges WHERE id=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			challenge := boulderChallenge{}
			err = rows.Scan(&challenge.ID, &challenge.AuthID, &challenge.Type, &challenge.Status, &challenge.Validated, &challenge.Token)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"ID", challenge.ID})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Type", challenge.Type})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Status", challenge.Status})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Validated", challenge.Validated})
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Token", challenge.Token})

			Link := NameValue{"Authorization", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/authz/" + challenge.AuthID + "\">" + challenge.AuthID + "</a>")}
			ChallengeDetails.Rows = append(ChallengeDetails.Rows, Link)
		}
	}

	return ChallengeDetails, nil
}

// boulderCertificate contains the data representing an ACME certificate in boulder
type boulderCertificate struct {
	ID             string
	RegistrationID string
	Serial         string
	IssuedName     string
	Status         string
	Issued         string
	Expires        string
}

// boulderReverseName as domains are stored in reverse order in boulder...
func boulderReverseName(domain string) string {
	labels := strings.Split(domain, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// GetCertificates returns the list of certificates, optionally only for a given account ID
func GetCertificates(w http.ResponseWriter, r *http.Request, forAccount string) (ListData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ListData{}, err
	}

	defer db.Close()

	Certificates := ListData{
		Title:      "Certificates",
		TableClass: "certificates_list",
		Header:     []template.HTML{"ID", "Account ID", "Serial", "Issued Name", "Status", "Issued", "Expires"},
	}

	if forAccount != "" {
		Certificates.TableClass = "rel_certificates_list"
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		Certificates.TableClass += " backend_stepca"

		revokeds, err := stepcaGetRevokeds(db)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		rows, err = db.Query("SELECT nvalue FROM acme_certs")
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			certificate := stepcaCert{}
			err = json.Unmarshal(row, &certificate)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}

			if forAccount == "" || certificate.AccountID == forAccount {
				var block *pem.Block
				var crt *x509.Certificate
				for len(certificate.Leaf) > 0 {
					block, certificate.Leaf = pem.Decode(certificate.Leaf)
					if block == nil {
						break
					}
					if block.Type != "CERTIFICATE" {
						errorHandler(w, r, err, http.StatusInternalServerError)
						return ListData{}, errors.New("error decoding PEM: data contains block that is not a certificate")
					}
					crt, err = x509.ParseCertificate(block.Bytes)
					if err != nil {
						errorHandler(w, r, err, http.StatusInternalServerError)
						return ListData{}, errors.Wrapf(err, "error parsing x509 certificate")
					}
				}
				if len(certificate.Leaf) > 0 {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return ListData{}, errors.New("error decoding PEM: unexpected data")
				}

				status := "good"
				if _, ok := revokeds[crt.SerialNumber.Text(10)]; ok {
					if time.Now().After(crt.NotAfter) {
						status = "revoked / expired"
					} else {
						status = "revoked"
					}
				} else if time.Now().After(crt.NotAfter) {
					status = "expired"
				}

				cert := make([]string, 0)
				cert = append(cert, certificate.ID)
				cert = append(cert, certificate.AccountID)
				cert = append(cert, crt.SerialNumber.Text(10))
				iss := strings.Join(crt.DNSNames, ", ")
				for _, ip := range crt.IPAddresses {
					if iss != "" {
						iss += ", "
					}
					iss += ip.String()
				}
				cert = append(cert, iss)
				cert = append(cert, status)
				cert = append(cert, crt.NotBefore.String())
				cert = append(cert, crt.NotAfter.String())

				if r.URL.Query().Get("active") != "" {
					if status == "good" {
						Certificates.Rows = append(Certificates.Rows, toAnyList(cert))
					}
				} else if r.URL.Query().Get("expired") != "" {
					if status == "expired" || status == "revoked / expired" {
						Certificates.Rows = append(Certificates.Rows, toAnyList(cert))
					}
				} else if r.URL.Query().Get("revoked") != "" {
					if status == "revoked" || status == "revoked / expired" {
						Certificates.Rows = append(Certificates.Rows, toAnyList(cert))
					}
				} else {
					Certificates.Rows = append(Certificates.Rows, toAnyList(cert))
				}
			}
		}
	} else {
		where := ""
		if r.URL.Query().Get("active") != "" {
			where = " WHERE cs.revokedDate='0000-00-00 00:00:00' AND cs.notAfter >= NOW()"
		} else if r.URL.Query().Get("expired") != "" {
			where = " WHERE cs.notAfter < NOW()"
		} else if r.URL.Query().Get("revoked") != "" {
			where = " WHERE cs.revokedDate<>'0000-00-00 00:00:00'"
		}

		if forAccount == "" {
			rows, err = db.Query("SELECT c.id, c.registrationID, c.serial, n.reversedName, CASE WHEN cs.notAfter < NOW() THEN CASE WHEN cs.status <> 'good' THEN concat(cs.status, ' / expired') ELSE 'expired' END ELSE cs.status END AS status, c.issued, c.expires FROM certificates c JOIN certificateStatus cs ON cs.id = c.id JOIN issuedNames n ON n.serial = c.serial" + where)
		} else if where == "" {
			rows, err = db.Query("SELECT c.id, c.registrationID, c.serial, n.reversedName, CASE WHEN cs.notAfter < NOW() THEN CASE WHEN cs.status <> 'good' THEN concat(cs.status, ' / expired') ELSE 'expired' END ELSE cs.status END AS status, c.issued, c.expires FROM certificates c JOIN certificateStatus cs ON cs.id = c.id JOIN issuedNames n ON n.serial = c.serial WHERE registrationID=?", forAccount)
		} else {
			rows, err = db.Query("SELECT c.id, c.registrationID, c.serial, n.reversedName, CASE WHEN cs.notAfter < NOW() THEN CASE WHEN cs.status <> 'good' THEN concat(cs.status, ' / expired') ELSE 'expired' END ELSE cs.status END AS status, c.issued, c.expires FROM certificates c JOIN certificateStatus cs ON cs.id = c.id JOIN issuedNames n ON n.serial = c.serial"+where+" AND registrationID=?", forAccount)
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ListData{}, err
		}

		for rows.Next() {
			certificate := boulderCertificate{}
			err = rows.Scan(&certificate.ID, &certificate.RegistrationID, &certificate.Serial, &certificate.IssuedName, &certificate.Status, &certificate.Issued, &certificate.Expires)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ListData{}, err
			}
			certificate.IssuedName = boulderReverseName(certificate.IssuedName)

			Certificates.Rows = append(Certificates.Rows, RangeStructer(certificate))
		}
	}

	return Certificates, nil
}

// boulderCertificateExtra contains more detailed data of an ACME certificate in boulder
type boulderCertificateExtra struct {
	ID                 int
	RegistrationID     int
	Serial             string
	IssuedName         string
	Digest             string
	Issued             string
	Expires            string
	SubscriberApproved bool
	Status             string
	OCSPLastUpdate     string
	Revoked            string
	RevokedReason      int
	LastNagSent        string
	NotAfter           string
	IsExpired          bool
}

// stepcaCert contains ACME certificates in step-ca, where the struct is called dbCert
type stepcaCert struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"createdAt"`
	AccountID     string    `json:"accountID"`
	OrderID       string    `json:"orderID"`
	Leaf          []byte    `json:"leaf"`
	Intermediates []byte    `json:"intermediates"`
}

// getReasonText converts a numeric ACME revoke reason into a string
func getReasonText(RevokedReason int, Revoked string) string {
	reasonText := ""
	switch RevokedReason {
	case 0:
		if Revoked != "0000-00-00 00:00:00" {
			reasonText = " - Unspecified"
		}
	case 1:
		reasonText = " - Key Compromise"
	case 2:
		reasonText = " - CA Compromise"
	case 3:
		reasonText = " - Affiliation Changed"
	case 4:
		reasonText = " - Superseded"
	case 5:
		reasonText = " - Cessation Of Operation"
	case 6:
		reasonText = " - Certificate Hold"
	case 8:
		reasonText = " - Remove From CRL"
	case 9:
		reasonText = " - Privilege Withdrawn"
	case 10:
		reasonText = " - AA Compromise"
	default:
		reasonText = "Unknown reason number: " + strconv.Itoa(RevokedReason)
	}

	return reasonText
}

// GetCertificate returns a certificate with the given id or serial
func GetCertificate(w http.ResponseWriter, r *http.Request, id string, serial string) (ShowData, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ShowData{}, err
	}

	defer db.Close()

	CertificateDetails := ShowData{
		Title:      "Certificate",
		TableClass: "certificate_show",
	}

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		revokeds, err := stepcaGetRevokeds(db)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		certDatas, err := stepcaCertsDatas(db)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		rows, err = db.Query("SELECT nvalue FROM acme_certs WHERE nkey=?", id)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			row := []byte{}
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			certificate := stepcaCert{}
			err = json.Unmarshal(row, &certificate)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}

			var block *pem.Block
			var crt *x509.Certificate
			for len(certificate.Leaf) > 0 {
				block, certificate.Leaf = pem.Decode(certificate.Leaf)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return ShowData{}, errors.New("error decoding PEM: data contains block that is not a certificate")
				}
				crt, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return ShowData{}, errors.Wrapf(err, "error parsing x509 certificate")
				}
			}
			if len(certificate.Leaf) > 0 {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, errors.New("error decoding PEM: unexpected data")
			}

			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"ID", certificate.ID})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Serial", crt.SerialNumber.Text(10)})
			iss := strings.Join(crt.DNSNames, ", ")
			for _, ip := range crt.IPAddresses {
				if iss != "" {
					iss += ", "
				}
				iss += ip.String()
			}
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Issued Name", iss})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Issuer", crt.Issuer.String()})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Subject", crt.Subject.String()})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Created At", certificate.CreatedAt.String()})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Issued", crt.NotBefore.String()})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Expires", crt.NotAfter.String()})
			if certData, ok := certDatas[crt.SerialNumber.Text(10)]; ok {
				CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Provisioner", certData.Provisioner.Name + " (" + certData.Provisioner.Type + ")"})
			}
			status := "good"
			if _, ok := revokeds[crt.SerialNumber.Text(10)]; ok {
				if time.Now().After(crt.NotAfter) {
					status = "revoked / expired"
				} else {
					status = "revoked"
				}
			} else if time.Now().After(crt.NotAfter) {
				status = "expired"
			}
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Status", status})
			if revoked, ok := revokeds[crt.SerialNumber.Text(10)]; ok {
				CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked At", revoked.RevokedAt.String()})
				if revoked.Reason == "" {
					reasonText := getReasonText(revoked.ReasonCode, "")
					CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked Reason", strconv.Itoa(revoked.ReasonCode) + reasonText})
				} else {
					CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked Reason", strconv.Itoa(revoked.ReasonCode) + " - " + revoked.Reason})
				}
				CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoke Provisioner", revoked.ProvisionerID})
				v := "false"
				if revoked.ACME {
					v = "true"
				}
				CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked ACME?", v})
				v = "false"
				if revoked.MTLS {
					v = "true"
				}
				CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked mTLS?", v})
			}
			v := "false"
			if time.Now().After(crt.NotAfter) {
				v = "true"
			}
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Is Expired", v})

			Link := NameValue{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + certificate.AccountID + "\">" + certificate.AccountID + "</a>")}
			CertificateDetails.Rows = append(CertificateDetails.Rows, Link)
			Link = NameValue{"Order", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/orders/" + certificate.OrderID + "\">" + certificate.OrderID + "</a>")}
			CertificateDetails.Rows = append(CertificateDetails.Rows, Link)

			// TODO: find a way to revoke for step-ca ??
			//
			//if row.Revoked == "0000-00-00 00:00:00" {
			//	revokeHTML, err := tmpls.RenderSingle("views/revoke-partial.tmpl", struct{ Serial string }{Serial: row.Serial})
			//	if err != nil {
			//		errorHandler(w, r, err, http.StatusInternalServerError)
			//		return CertificateShow{}, err
			//	}
			//	CertificateDetails.Extra = append(CertificateDetails.Extra, template.HTML(revokeHTML))
			//}
		}
	} else {
		selectWhere := "SELECT c.id, c.registrationID, c.serial, n.reversedName, c.digest, c.issued, c.expires, cs.subscriberApproved, CASE WHEN cs.notAfter < NOW() THEN CASE WHEN cs.status <> 'good' THEN concat(cs.status, ' / expired') ELSE 'expired' END ELSE cs.status END AS status, cs.ocspLastUpdated, cs.revokedDate, cs.revokedReason, cs.lastExpirationNagSent, cs.notAfter, cs.isExpired FROM certificates c JOIN certificateStatus cs ON cs.id = c.id JOIN issuedNames n ON n.serial = c.serial WHERE "

		if serial != "" {
			rows, err = db.Query(selectWhere+"c.serial=?", serial)
		} else {
			rows, err = db.Query(selectWhere+"c.id=?", id)
		}
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ShowData{}, err
		}

		for rows.Next() {
			certificate := boulderCertificateExtra{}
			err = rows.Scan(&certificate.ID, &certificate.RegistrationID, &certificate.Serial, &certificate.IssuedName, &certificate.Digest, &certificate.Issued, &certificate.Expires, &certificate.SubscriberApproved, &certificate.Status, &certificate.OCSPLastUpdate, &certificate.Revoked, &certificate.RevokedReason, &certificate.LastNagSent, &certificate.NotAfter, &certificate.IsExpired)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return ShowData{}, err
			}
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"ID", strconv.Itoa(certificate.ID)})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Serial", certificate.Serial})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Issued Name", boulderReverseName(certificate.IssuedName)})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Digest", certificate.Digest})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Issued", certificate.Issued})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Expires", certificate.Expires})
			v := "false"
			if certificate.SubscriberApproved {
				v = "true"
			}
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Subscriber Approved", v})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Status", certificate.Status})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"OCSP Last Update", certificate.OCSPLastUpdate})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked", certificate.Revoked})
			reasonText := getReasonText(certificate.RevokedReason, certificate.Revoked)
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked Reason", strconv.Itoa(certificate.RevokedReason) + reasonText})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Last Expiration Nag Sent", certificate.LastNagSent})
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Not After", certificate.NotAfter})
			v = "false"
			if certificate.IsExpired {
				v = "true"
			}
			CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Is Expired", v})

			Link := NameValue{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + strconv.Itoa(certificate.RegistrationID) + "\">" + strconv.Itoa(certificate.RegistrationID) + "</a>")}
			CertificateDetails.Rows = append(CertificateDetails.Rows, Link)

			if certificate.Revoked == "0000-00-00 00:00:00" {
				revokeHTML, err := tmpls.RenderSingle("views/revoke-partial.tmpl", struct{ Serial string }{Serial: certificate.Serial})
				if err != nil {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return ShowData{}, err
				}
				CertificateDetails.Extra = append(CertificateDetails.Extra, template.HTML(revokeHTML))
			}
		}
	}

	return CertificateDetails, nil
}
