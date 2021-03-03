package main

import (
	"database/sql"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// BaseList is the generic base struct for showing lists of data
type BaseList struct {
	Title      string
	TableClass string
	Header     []template.HTML
}

// Account contains the data representing an ACME account
type Account struct {
	ID        int
	Status    string
	Contact   string
	Agreement string
	InitialIP net.IP
	CreatedAt string
}

// AccountList is a list of Account records
type AccountList struct {
	BaseList
	Rows []Account
}

// GetAccounts returns the list of accounts
func GetAccounts(w http.ResponseWriter, r *http.Request) (AccountList, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AccountList{}, err
	}

	defer db.Close()

	rows, err := db.Query("SELECT id, status, contact, agreement, initialIP, createdAt FROM registrations")
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AccountList{}, err
	}

	Accounts := AccountList{
		BaseList: BaseList{
			Title:      "Accounts",
			TableClass: "accounts_list",
			Header:     []template.HTML{"ID", "Status", "Contact", "Agreement", "Initial IP", "Created"},
		},
		Rows: []Account{},
	}

	for rows.Next() {
		row := Account{}
		err = rows.Scan(&row.ID, &row.Status, &row.Contact, &row.Agreement, &row.InitialIP, &row.CreatedAt)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return AccountList{}, err
		}
		Accounts.Rows = append(Accounts.Rows, row)
	}

	return Accounts, nil
}

// Order contains the data representing an ACME order
type Order struct {
	ID             int
	RegistrationID int
	CertSerial     string
	RequestedName  string
	BeganProc      bool
	Created        string
	Expires        string
}

// OrderList is a list of Order records
type OrderList struct {
	BaseList
	Rows []Order
}

// NameValue is a pair of a name and a value
type NameValue struct {
	Name  string
	Value string
}

// BaseShow is the generic base struct for showing an individual data record
type BaseShow struct {
	Title      string
	TableClass string
	Rows       []NameValue
	Links      []NameValHTML
	Extra      []template.HTML
}

// AccountShow contains the data of an ACME account and its related data lists
type AccountShow struct {
	BaseShow
	Related  []CertificateList
	Related2 []OrderList
}

// GetAccount returns an account
func GetAccount(w http.ResponseWriter, r *http.Request, id int) (AccountShow, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AccountShow{}, err
	}

	defer db.Close()

	rows, err := db.Query("SELECT c.id, c.registrationID, c.serial, n.reversedName, CASE WHEN cs.notAfter < NOW() THEN 'expired' ELSE cs.status END AS status, c.issued, c.expires FROM certificates c JOIN certificateStatus cs ON cs.id = c.id JOIN issuedNames n ON n.serial = c.serial WHERE registrationID=?", strconv.Itoa(id))
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AccountShow{}, err
	}

	Certificates := CertificateList{
		BaseList: BaseList{
			Title:      "Certificates",
			TableClass: "rel_certificates_list",
			Header:     []template.HTML{"ID", "Account ID", "Serial", "Issued Name", "Status", "Issued", "Expires"},
		},
		Rows: []Certificate{},
	}

	for rows.Next() {
		row := Certificate{}
		err = rows.Scan(&row.ID, &row.RegistrationID, &row.Serial, &row.IssuedName, &row.Status, &row.Issued, &row.Expires)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return AccountShow{}, err
		}
		row.IssuedName = ReverseName(row.IssuedName)
		Certificates.Rows = append(Certificates.Rows, row)
	}

	rows, err = db.Query("SELECT o.id, o.registrationID, o.certificateSerial, n.reversedName, o.beganProcessing, o.created, o.expires FROM orders o JOIN requestedNames n ON n.orderID = o.id WHERE o.registrationID=?", strconv.Itoa(id))
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AccountShow{}, err
	}

	Orders := OrderList{
		BaseList: BaseList{
			Title:      "Orders",
			TableClass: "rel_orders_list",
			Header:     []template.HTML{"ID", "Account ID", "Certificate Serial", "Requested Name", "Began Processing?", "Created", "Expires"},
		},
		Rows: []Order{},
	}

	for rows.Next() {
		row := Order{}
		err = rows.Scan(&row.ID, &row.RegistrationID, &row.CertSerial, &row.RequestedName, &row.BeganProc, &row.Created, &row.Expires)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return AccountShow{}, err
		}
		row.RequestedName = ReverseName(row.RequestedName)
		Orders.Rows = append(Orders.Rows, row)
	}

	rows, err = db.Query("SELECT id, status, contact, agreement, initialIP, createdAt FROM registrations WHERE id=?", strconv.Itoa(id))
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AccountShow{}, err
	}

	AccountDetails := AccountShow{
		BaseShow: BaseShow{
			Title:      "Account",
			TableClass: "account_show",
			Rows:       []NameValue{},
		},
		Related:  []CertificateList{Certificates},
		Related2: []OrderList{Orders},
	}

	for rows.Next() {
		row := Account{}
		err = rows.Scan(&row.ID, &row.Status, &row.Contact, &row.Agreement, &row.InitialIP, &row.CreatedAt)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return AccountShow{}, err
		}
		AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"ID", strconv.Itoa(row.ID)})
		AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Status", row.Status})
		AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Contact", row.Contact})
		AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Agreement", row.Agreement})
		AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Initial IP", row.InitialIP.String()})
		AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Created At", row.CreatedAt})
	}

	return AccountDetails, nil
}

// GetOrders returns the list of orders
func GetOrders(w http.ResponseWriter, r *http.Request) (OrderList, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return OrderList{}, err
	}

	defer db.Close()

	rows, err := db.Query("SELECT o.id, o.registrationID, o.certificateSerial, n.reversedName, o.beganProcessing, o.created, o.expires FROM orders o JOIN requestedNames n ON n.orderID = o.id")
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return OrderList{}, err
	}

	Orders := OrderList{
		BaseList: BaseList{
			Title:      "Orders",
			TableClass: "orders_list",
			Header:     []template.HTML{"ID", "Account ID", "Certificate Serial", "Requested Name", "Began Processing?", "Created", "Expires"},
		},
		Rows: []Order{},
	}

	for rows.Next() {
		row := Order{}
		err = rows.Scan(&row.ID, &row.RegistrationID, &row.CertSerial, &row.RequestedName, &row.BeganProc, &row.Created, &row.Expires)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return OrderList{}, err
		}
		row.RequestedName = ReverseName(row.RequestedName)
		Orders.Rows = append(Orders.Rows, row)
	}

	return Orders, nil
}

// Auth contains the data representing an ACME auth
type Auth struct {
	ID             string
	Identifier     string
	RegistrationID int
	Status         string
	Expires        string
}

// AuthList is a list of Auth records
type AuthList struct {
	BaseList
	Rows []Auth
}

// OrderShow contains the data of an ACME order and its related data lists
type OrderShow struct {
	BaseShow
	Related  []AuthList
	Related2 []BaseList
}

// Helper method from sa/model.go
var uintToStatus = map[int]string{
	0: "pending",
	1: "valid",
	2: "invalid",
	3: "deactivated",
	4: "revoked",
}

// GetOrder returns an order with the given id
func GetOrder(w http.ResponseWriter, r *http.Request, id int) (OrderShow, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return OrderShow{}, err
	}

	defer db.Close()

	query := ""
	if tableExists(db, "authz") {
		ident := "identifier"
		if columnExists(db, "authz", "identifierValue") {
			ident = "identifierValue"
		}
		query = "SELECT id, " + ident + ", registrationID, status, expires FROM authz WHERE id IN (SELECT authzID FROM orderToAuthz WHERE orderID=?)"
	}
	if tableExists(db, "authz2") {
		if query != "" {
			query = query + " UNION "
		}
		query = query + "SELECT id, identifierValue, registrationID, status, expires FROM authz2 WHERE id IN (SELECT authzID FROM orderToAuthz2 WHERE orderID=?)"
	}
	var rows *sql.Rows
	if tableExists(db, "authz") && tableExists(db, "authz2") {
		rows, err = db.Query(query, strconv.Itoa(id), strconv.Itoa(id))
	} else {
		rows, err = db.Query(query, strconv.Itoa(id))
	}
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return OrderShow{}, err
	}

	Authz := AuthList{
		BaseList: BaseList{
			Title:      "Authorizations",
			TableClass: "rel_authz_list",
			Header:     []template.HTML{"ID", "Identifier", "Account ID", "Status", "Expires"},
		},
		Rows: []Auth{},
	}

	for rows.Next() {
		row := Auth{}
		err = rows.Scan(&row.ID, &row.Identifier, &row.RegistrationID, &row.Status, &row.Expires)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return OrderShow{}, err
		}
		if s, err := strconv.Atoi(row.Status); err == nil {
			row.Status = uintToStatus[s]
		}
		Authz.Rows = append(Authz.Rows, row)
	}

	rows, err = db.Query("SELECT o.id, o.registrationID, o.certificateSerial, n.reversedName, o.beganProcessing, o.created, o.expires FROM orders o JOIN requestedNames n ON n.orderID = o.id WHERE o.id=?", strconv.Itoa(id))
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return OrderShow{}, err
	}

	OrderDetails := OrderShow{
		BaseShow: BaseShow{
			Title:      "Order",
			TableClass: "order_show",
			Rows:       []NameValue{},
			Links:      []NameValHTML{},
		},
		Related: []AuthList{Authz},
	}

	for rows.Next() {
		row := Order{}
		err = rows.Scan(&row.ID, &row.RegistrationID, &row.CertSerial, &row.RequestedName, &row.BeganProc, &row.Created, &row.Expires)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return OrderShow{}, err
		}
		OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"ID", strconv.Itoa(row.ID)})
		v := "false"
		if row.BeganProc {
			v = "true"
		}
		OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Began Processing?", v})
		OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Created", row.Created})
		OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Expires", row.Expires})

		OrderDetails.Links = append(OrderDetails.Links, NameValHTML{"Certificate", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/certificates/" + row.CertSerial + "\">" + row.CertSerial + "</a>")})
		OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Requested Name", ReverseName(row.RequestedName)})
		OrderDetails.Links = append(OrderDetails.Links, NameValHTML{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + strconv.Itoa(row.RegistrationID) + "\">" + strconv.Itoa(row.RegistrationID) + "</a>")})
	}

	return OrderDetails, nil
}

func tableExists(db *sql.DB, tableName string) bool {
	rows, _ := db.Query("SHOW TABLES LIKE '" + tableName + "'")
	return rows.Next()
}

func columnExists(db *sql.DB, tableName, columnName string) bool {
	rows, _ := db.Query("SHOW COLUMNS FROM `" + tableName + "` LIKE '" + columnName + "'")
	return rows.Next()
}

// GetAuthz returns the list of authz
func GetAuthz(w http.ResponseWriter, r *http.Request) (AuthList, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AuthList{}, err
	}

	defer db.Close()

	query := ""
	if tableExists(db, "authz") {
		if columnExists(db, "authz", "identifierValue") {
			query = "SELECT id, identifierValue, registrationID, status, expires FROM authz"
		} else {
			query = "SELECT id, identifier, registrationID, status, expires FROM authz"
		}
	}
	if tableExists(db, "authz2") {
		if query != "" {
			query = query + " UNION "
		}
		query = query + "SELECT id, identifierValue, registrationID, status, expires FROM authz2"
	}
	rows, err := db.Query(query)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AuthList{}, err
	}

	Authz := AuthList{
		BaseList: BaseList{
			Title:      "Authorizations",
			TableClass: "authz_list",
			Header:     []template.HTML{"ID", "Identifier", "Account ID", "Status", "Expires"},
		},
		Rows: []Auth{},
	}

	for rows.Next() {
		row := Auth{}
		err = rows.Scan(&row.ID, &row.Identifier, &row.RegistrationID, &row.Status, &row.Expires)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return AuthList{}, err
		}
		if s, err := strconv.Atoi(row.Status); err == nil {
			row.Status = uintToStatus[s]
		}
		Authz.Rows = append(Authz.Rows, row)
	}

	return Authz, nil
}

// Challenge contains the data representing an ACME challenge
type Challenge struct {
	ID        int
	AuthID    string
	Type      string
	Status    string
	Validated string
	Token     string
	KeyAuth   string
}

// ChallengeList is a list of Challenge records
type ChallengeList struct {
	BaseList
	Rows []Challenge
}

// NameValHTML is a pair of a name and an HTML value
type NameValHTML struct {
	Name  string
	Value template.HTML
}

// AuthShow contains the data of an ACME auth and its related data lists
type AuthShow struct {
	BaseShow
	Related  []ChallengeList
	Related2 []BaseList
}

// GetAuth returns an auth with the given id
func GetAuth(w http.ResponseWriter, r *http.Request, id string) (AuthShow, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AuthShow{}, err
	}

	defer db.Close()

	rows, err := db.Query("SELECT id, authorizationID, type, status, validated, token, keyAuthorization FROM challenges WHERE authorizationID=?", id)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return AuthShow{}, err
	}

	Challenges := ChallengeList{
		BaseList: BaseList{
			Title:      "Challenges",
			TableClass: "rel_challenges_list",
			Header:     []template.HTML{"ID", "Authorization ID", "Type", "Status", "Validated", "Token", "Key Authorization"},
		},
		Rows: []Challenge{},
	}

	for rows.Next() {
		row := Challenge{}
		err = rows.Scan(&row.ID, &row.AuthID, &row.Type, &row.Status, &row.Validated, &row.Token, &row.KeyAuth)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return AuthShow{}, err
		}
		Challenges.Rows = append(Challenges.Rows, row)
	}

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
		return AuthShow{}, err
	}

	AuthDetails := AuthShow{
		BaseShow: BaseShow{
			Title:      "Authorization",
			TableClass: "auth_show",
			Rows:       []NameValue{},
			Links:      []NameValHTML{},
		},
		Related: []ChallengeList{Challenges},
	}

	for rows.Next() {
		row := Auth{}
		validationError := sql.NullString{}
		validationRecord := sql.NullString{}
		err = rows.Scan(&row.ID, &row.Identifier, &row.RegistrationID, &row.Status, &row.Expires, &validationError, &validationRecord)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return AuthShow{}, err
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

		Link := NameValHTML{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + strconv.Itoa(row.RegistrationID) + "\">" + strconv.Itoa(row.RegistrationID) + "</a>")}
		AuthDetails.Links = append(AuthDetails.Links, Link)
	}

	return AuthDetails, nil
}

// GetChallenges returns the list of challenges
func GetChallenges(w http.ResponseWriter, r *http.Request) (ChallengeList, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ChallengeList{}, err
	}

	defer db.Close()

	rows, err := db.Query("SELECT id, authorizationID, type, status, validated, token, keyAuthorization FROM challenges")
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ChallengeList{}, err
	}

	Challenges := ChallengeList{
		BaseList: BaseList{
			Title:      "Challenges",
			TableClass: "challenges_list",
			Header:     []template.HTML{"ID", "Authorization ID", "Type", "Status", "Validated", "Token", "Key Authorization"},
		},
		Rows: []Challenge{},
	}

	for rows.Next() {
		row := Challenge{}
		err = rows.Scan(&row.ID, &row.AuthID, &row.Type, &row.Status, &row.Validated, &row.Token, &row.KeyAuth)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ChallengeList{}, err
		}
		Challenges.Rows = append(Challenges.Rows, row)
	}

	return Challenges, nil
}

// ChallengeShow contains the data of an ACME challenge and its related data lists
type ChallengeShow struct {
	BaseShow
	Related  []ChallengeList
	Related2 []BaseList
}

// GetChallenge returns a challenge with the given id
func GetChallenge(w http.ResponseWriter, r *http.Request, id int) (ChallengeShow, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ChallengeShow{}, err
	}

	defer db.Close()

	rows, err := db.Query("SELECT id, authorizationID, type, status, validated, token, keyAuthorization FROM challenges WHERE id=?", id)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return ChallengeShow{}, err
	}

	ChallengeDetails := ChallengeShow{
		BaseShow: BaseShow{
			Title:      "Challenge",
			TableClass: "challenge_show",
			Rows:       []NameValue{},
			Links:      []NameValHTML{},
		},
		Related: []ChallengeList{},
	}

	for rows.Next() {
		row := Challenge{}
		err = rows.Scan(&row.ID, &row.AuthID, &row.Type, &row.Status, &row.Validated, &row.Token, &row.KeyAuth)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return ChallengeShow{}, err
		}
		ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"ID", strconv.Itoa(row.ID)})
		ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Type", row.Type})
		ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Status", row.Status})
		ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Validated", row.Validated})
		ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Token", row.Token})
		ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"KeyAuth", row.KeyAuth})

		Link := NameValHTML{"Authorization", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/authz/" + row.AuthID + "\">" + row.AuthID + "</a>")}
		ChallengeDetails.Links = append(ChallengeDetails.Links, Link)
	}

	return ChallengeDetails, nil
}

// Certificate contains the data representing an ACME certificate
type Certificate struct {
	ID             int
	RegistrationID int
	Serial         string
	IssuedName     string
	Status         string
	Issued         string
	Expires        string
}

// CertificateList is a list of Certificate records
type CertificateList struct {
	BaseList
	Rows []Certificate
}

// ReverseName as domains are stored in reverse order...
func ReverseName(domain string) string {
	labels := strings.Split(domain, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// GetCertificates returns the list of certificates
func GetCertificates(w http.ResponseWriter, r *http.Request) (CertificateList, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return CertificateList{}, err
	}

	defer db.Close()

	where := ""
	if r.URL.Query().Get("active") != "" {
		where = " WHERE cs.revokedDate='0000-00-00 00:00:00' AND cs.notAfter >= NOW()"
	} else if r.URL.Query().Get("expired") != "" {
		where = " WHERE cs.revokedDate='0000-00-00 00:00:00' AND cs.notAfter < NOW()"
	} else if r.URL.Query().Get("revoked") != "" {
		where = " WHERE cs.revokedDate<>'0000-00-00 00:00:00'"
	}

	rows, err := db.Query("SELECT c.id, c.registrationID, c.serial, n.reversedName, CASE WHEN cs.notAfter < NOW() THEN 'expired' ELSE cs.status END AS status, c.issued, c.expires FROM certificates c JOIN certificateStatus cs ON cs.id = c.id JOIN issuedNames n ON n.serial = c.serial" + where)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return CertificateList{}, err
	}

	Certificates := CertificateList{
		BaseList: BaseList{
			Title:      "Certificates",
			TableClass: "certificates_list",
			Header:     []template.HTML{"ID", "Account ID", "Serial", "Issued Name", "Status", "Issued", "Expires"},
		},
		Rows: []Certificate{},
	}

	for rows.Next() {
		row := Certificate{}
		err = rows.Scan(&row.ID, &row.RegistrationID, &row.Serial, &row.IssuedName, &row.Status, &row.Issued, &row.Expires)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return CertificateList{}, err
		}
		row.IssuedName = ReverseName(row.IssuedName)
		Certificates.Rows = append(Certificates.Rows, row)
	}

	return Certificates, nil
}

// CertificateShow contains the data of an ACME certificate and its related data lists
type CertificateShow struct {
	BaseShow
	Related  []BaseList
	Related2 []BaseList
}

// CertificateExtra contains more detailed data of an ACME certificate
type CertificateExtra struct {
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

func _getReasonText(RevokedReason int, Revoked string) string {
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
	}

	return reasonText
}

// GetCertificate returns a certificate with the given id or serial
func GetCertificate(w http.ResponseWriter, r *http.Request, id int, serial string) (CertificateShow, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return CertificateShow{}, err
	}

	defer db.Close()

	var rows *sql.Rows
	selectWhere := "SELECT c.id, c.registrationID, c.serial, n.reversedName, c.digest, c.issued, c.expires, cs.subscriberApproved, CASE WHEN cs.notAfter < NOW() THEN 'expired' ELSE cs.status END AS status, cs.ocspLastUpdated, cs.revokedDate, cs.revokedReason, cs.lastExpirationNagSent, cs.notAfter, cs.isExpired FROM certificates c JOIN certificateStatus cs ON cs.id = c.id JOIN issuedNames n ON n.serial = c.serial WHERE "

	if serial != "" {
		rows, err = db.Query(selectWhere+"c.serial=?", serial)
	} else {
		rows, err = db.Query(selectWhere+"c.id=?", id)
	}
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return CertificateShow{}, err
	}

	CertificateDetails := CertificateShow{
		BaseShow: BaseShow{
			Title:      "Certificate",
			TableClass: "certificate_show",
			Rows:       []NameValue{},
			Links:      []NameValHTML{},
		},
	}

	for rows.Next() {
		row := CertificateExtra{}
		err = rows.Scan(&row.ID, &row.RegistrationID, &row.Serial, &row.IssuedName, &row.Digest, &row.Issued, &row.Expires, &row.SubscriberApproved, &row.Status, &row.OCSPLastUpdate, &row.Revoked, &row.RevokedReason, &row.LastNagSent, &row.NotAfter, &row.IsExpired)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return CertificateShow{}, err
		}
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"ID", strconv.Itoa(row.ID)})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Serial", row.Serial})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Issued Name", ReverseName(row.IssuedName)})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Digest", row.Digest})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Issued", row.Issued})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Expires", row.Expires})
		v := "false"
		if row.SubscriberApproved {
			v = "true"
		}
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Subscriber Approved", v})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Status", row.Status})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"OCSP Last Update", row.OCSPLastUpdate})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked", row.Revoked})
		reasonText := _getReasonText(row.RevokedReason, row.Revoked)
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked Reason", strconv.Itoa(row.RevokedReason) + reasonText})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Last Expiration Nag Sent", row.LastNagSent})
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Not After", row.NotAfter})
		v = "false"
		if row.IsExpired {
			v = "true"
		}
		CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Is Expired", v})

		Link := NameValHTML{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + strconv.Itoa(row.RegistrationID) + "\">" + strconv.Itoa(row.RegistrationID) + "</a>")}
		CertificateDetails.Links = append(CertificateDetails.Links, Link)

		if row.Revoked == "0000-00-00 00:00:00" {
			revokeHTML, err := tmpls.RenderSingle("views/revoke-partial.tmpl", struct{ Serial string }{Serial: row.Serial})
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return CertificateShow{}, err
			}
			CertificateDetails.Extra = append(CertificateDetails.Extra, template.HTML(revokeHTML))
		}
	}

	return CertificateDetails, nil
}
