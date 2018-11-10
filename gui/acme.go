package main

import (
    "database/sql"
    "html/template"
    "net"
    "net/http"
    "strconv"
)

type BaseList struct {
    Title      string
    TableClass string
    Header     []template.HTML
}

type Account struct {
    Id        int
    Status    string
    Contact   string
    Agreement string
    InitialIp net.IP
    CreatedAt string
}

type AccountList struct {
    BaseList
    Rows []Account
}

func GetAccounts(w http.ResponseWriter, r *http.Request) (AccountList, error){
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
        err = rows.Scan(&row.Id, &row.Status, &row.Contact, &row.Agreement, &row.InitialIp, &row.CreatedAt)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return AccountList{}, err
        }
        Accounts.Rows = append(Accounts.Rows, row)
    }

    return Accounts, nil
}

type Order struct {
    Id             int
    RegistrationId int
    Expires        string
    CertSerial     string
    BeganProc      bool
    Created        string
}

type OrderList struct {
    BaseList
    Rows []Order
}

type NameValue struct {
    Name  string
    Value string
}

type BaseShow struct {
    Title      string
    TableClass string
    Rows       []NameValue
    Links      []NameValHtml
    Extra      []template.HTML
}

type AccountShow struct {
    BaseShow
    Related  []CertificateList
    Related2 []OrderList
}

func GetAccount(w http.ResponseWriter, r *http.Request, id int) (AccountShow, error) {
    db, err := sql.Open(dbType, dbConn)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return AccountShow{}, err
    }

    defer db.Close()

    rows, err := db.Query("SELECT c.id, c.registrationID, c.serial, CASE WHEN cs.notAfter < NOW() THEN 'expired' ELSE cs.status END AS status, c.issued, c.expires FROM certificates c JOIN certificateStatus cs ON cs.id = c.id WHERE registrationID=?", strconv.Itoa(id))
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return AccountShow{}, err
    }

    Certificates := CertificateList{
        BaseList: BaseList{
            Title:      "Certificates",
            TableClass: "rel_certificates_list",
            Header:     []template.HTML{"ID", "Account ID", "Serial", "Status", "Issued", "Expires"},
        },
        Rows: []Certificate{},
    }

    for rows.Next() {
        row := Certificate{}
        err = rows.Scan(&row.Id, &row.RegistrationId, &row.Serial, &row.Status, &row.Issued, &row.Expires)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return AccountShow{}, err
        }
        Certificates.Rows = append(Certificates.Rows, row)
    }

    rows, err = db.Query("SELECT id, registrationID, expires, certificateSerial, beganProcessing, created FROM orders WHERE registrationID=?", strconv.Itoa(id))
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return AccountShow{}, err
    }

    Orders := OrderList{
        BaseList: BaseList{
            Title:      "Orders",
            TableClass: "rel_orders_list",
            Header:     []template.HTML{"ID", "Account ID", "Expires", "Certificate Serial", "Began Processing?", "Created"},
        },
        Rows: []Order{},
    }

    for rows.Next() {
        row := Order{}
        err = rows.Scan(&row.Id, &row.RegistrationId, &row.Expires, &row.CertSerial, &row.BeganProc, &row.Created)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return AccountShow{}, err
        }
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
        Related: []CertificateList{Certificates},
        Related2: []OrderList{Orders},
    }

    for rows.Next() {
        row := Account{}
        err = rows.Scan(&row.Id, &row.Status, &row.Contact, &row.Agreement, &row.InitialIp, &row.CreatedAt)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return AccountShow{}, err
        }
        AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"ID", strconv.Itoa(row.Id)})
        AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Status", row.Status})
        AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Contact", row.Contact})
        AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Agreement", row.Agreement})
        AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Initial IP", row.InitialIp.String()})
        AccountDetails.Rows = append(AccountDetails.Rows, NameValue{"Created At", row.CreatedAt})
    }

    return AccountDetails, nil
}

func GetOrders(w http.ResponseWriter, r *http.Request) (OrderList, error) {
    db, err := sql.Open(dbType, dbConn)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return OrderList{}, err
    }

    defer db.Close()

    rows, err := db.Query("SELECT id, registrationID, expires, certificateSerial, beganProcessing, created FROM orders")
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return OrderList{}, err
    }

    Orders := OrderList{
        BaseList: BaseList{
            Title:      "Orders",
            TableClass: "orders_list",
            Header:     []template.HTML{"ID", "Account ID", "Expires", "Certificate Serial", "Began Processing?", "Created"},
        },
        Rows: []Order{},
    }

    for rows.Next() {
        row := Order{}
        err = rows.Scan(&row.Id, &row.RegistrationId, &row.Expires, &row.CertSerial, &row.BeganProc, &row.Created)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return OrderList{}, err
        }
        Orders.Rows = append(Orders.Rows, row)
    }

    return Orders, nil
}

type Auth struct {
    Id             string
    Identifier     string
    RegistrationId int
    Status         string
    Expires        string
    Combinations   string
}

type AuthList struct {
    BaseList
    Rows []Auth
}

type OrderShow struct {
    BaseShow
    Related  []AuthList
    Related2 []BaseList
}

func GetOrder(w http.ResponseWriter, r *http.Request, id int) (OrderShow, error) {
    db, err := sql.Open(dbType, dbConn)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return OrderShow{}, err
    }

    defer db.Close()

    partial := "SELECT id, identifier, registrationID, status, expires, combinations FROM "
    where := " WHERE id IN (SELECT authzID FROM orderToAuthz WHERE orderID=?)"
    rows, err := db.Query(partial+"authz"+where+" UNION "+partial+"pendingAuthorizations"+where, strconv.Itoa(id), strconv.Itoa(id))
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return OrderShow{}, err
    }

    Authz := AuthList{
        BaseList: BaseList{
            Title:      "Authorizations",
            TableClass: "rel_authz_list",
            Header:     []template.HTML{"ID", "Identifier", "Account ID", "Status", "Expires", "Combinations"},
        },
        Rows: []Auth{},
    }

    for rows.Next() {
        row := Auth{}
        err = rows.Scan(&row.Id, &row.Identifier, &row.RegistrationId, &row.Status, &row.Expires, &row.Combinations)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return OrderShow{}, err
        }
        Authz.Rows = append(Authz.Rows, row)
    }

    rows, err = db.Query("SELECT id, registrationID, expires, certificateSerial, beganProcessing, created FROM orders WHERE id=?", strconv.Itoa(id))
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return OrderShow{}, err
    }

    OrderDetails := OrderShow{
        BaseShow: BaseShow{
            Title:      "Order",
            TableClass: "order_show",
            Rows:       []NameValue{},
            Links:      []NameValHtml{},
        },
        Related: []AuthList{Authz},
    }

    for rows.Next() {
        row := Order{}
        err = rows.Scan(&row.Id, &row.RegistrationId, &row.Expires, &row.CertSerial, &row.BeganProc, &row.Created)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return OrderShow{}, err
        }
        OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"ID", strconv.Itoa(row.Id)})
        OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Expires", row.Expires})
        v := "false"
        if row.BeganProc {
            v = "true"
        }
        OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Began Processing?", v})
        OrderDetails.Rows = append(OrderDetails.Rows, NameValue{"Created", row.Created})

        OrderDetails.Links = append(OrderDetails.Links, NameValHtml{"Certificate", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/certificates/" + row.CertSerial + "\">" + row.CertSerial + "</a>")})
        OrderDetails.Links = append(OrderDetails.Links, NameValHtml{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + strconv.Itoa(row.RegistrationId) + "\">" + strconv.Itoa(row.RegistrationId) + "</a>")})
    }

    return OrderDetails, nil
}

func GetAuthz(w http.ResponseWriter, r *http.Request) (AuthList, error) {
    db, err := sql.Open(dbType, dbConn)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return AuthList{}, err
    }

    defer db.Close()

    rows, err := db.Query("SELECT id, identifier, registrationID, status, expires, combinations FROM authz UNION SELECT id, identifier, registrationID, status, expires, combinations FROM pendingAuthorizations")
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return AuthList{}, err
    }

    Authz := AuthList{
        BaseList: BaseList{
            Title:      "Authorizations",
            TableClass: "authz_list",
            Header:     []template.HTML{"ID", "Identifier", "Account ID", "Status", "Expires", "Combinations"},
        },
        Rows: []Auth{},
    }

    for rows.Next() {
        row := Auth{}
        err = rows.Scan(&row.Id, &row.Identifier, &row.RegistrationId, &row.Status, &row.Expires, &row.Combinations)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return AuthList{}, err
        }
        Authz.Rows = append(Authz.Rows, row)
    }

    return Authz, nil
}

type Challenge struct {
    Id        int
    AuthId    string
    Type      string
    Status    string
    Validated string
    Token     string
    KeyAuth   string
}

type ChallengeList struct {
    BaseList
    Rows []Challenge
}

type NameValHtml struct {
    Name  string
    Value template.HTML
}

type AuthShow struct {
    BaseShow
    Related  []ChallengeList
    Related2 []BaseList
}

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
        err = rows.Scan(&row.Id, &row.AuthId, &row.Type, &row.Status, &row.Validated, &row.Token, &row.KeyAuth)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return AuthShow{}, err
        }
        Challenges.Rows = append(Challenges.Rows, row)
    }

    partial := "SELECT id, identifier, registrationID, status, expires, combinations FROM "
    where := " WHERE id IN (SELECT authzID FROM orderToAuthz WHERE id=?)"
    rows, err = db.Query(partial+"authz"+where+" UNION "+partial+"pendingAuthorizations"+where, id, id)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return AuthShow{}, err
    }

    AuthDetails := AuthShow{
        BaseShow: BaseShow{
            Title:      "Authorization",
            TableClass: "auth_show",
            Rows:       []NameValue{},
            Links:      []NameValHtml{},
        },
        Related: []ChallengeList{Challenges},
    }

    for rows.Next() {
        row := Auth{}
        err = rows.Scan(&row.Id, &row.Identifier, &row.RegistrationId, &row.Status, &row.Expires, &row.Combinations)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return AuthShow{}, err
        }
        AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"ID", row.Id})
        AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Identifier", row.Identifier})
        AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Status", row.Status})
        AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Expires", row.Expires})
        AuthDetails.Rows = append(AuthDetails.Rows, NameValue{"Combinations", row.Combinations})

        Link := NameValHtml{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + strconv.Itoa(row.RegistrationId) + "\">" + strconv.Itoa(row.RegistrationId) + "</a>")}
        AuthDetails.Links = append(AuthDetails.Links, Link)
    }

    return AuthDetails, nil
}

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
        err = rows.Scan(&row.Id, &row.AuthId, &row.Type, &row.Status, &row.Validated, &row.Token, &row.KeyAuth)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return ChallengeList{}, err
        }
        Challenges.Rows = append(Challenges.Rows, row)
    }

    return Challenges, nil
}

type ChallengeShow struct {
    BaseShow
    Related  []ChallengeList
    Related2 []BaseList
}

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
            Links:      []NameValHtml{},
        },
        Related: []ChallengeList{},
    }

    for rows.Next() {
        row := Challenge{}
        err = rows.Scan(&row.Id, &row.AuthId, &row.Type, &row.Status, &row.Validated, &row.Token, &row.KeyAuth)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return ChallengeShow{}, err
        }
        ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"ID", strconv.Itoa(row.Id)})
        ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Type", row.Type})
        ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Status", row.Status})
        ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Validated", row.Validated})
        ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"Token", row.Token})
        ChallengeDetails.Rows = append(ChallengeDetails.Rows, NameValue{"KeyAuth", row.KeyAuth})

        Link := NameValHtml{"Authorization", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/authz/" + row.AuthId + "\">" + row.AuthId + "</a>")}
        ChallengeDetails.Links = append(ChallengeDetails.Links, Link)
    }

    return ChallengeDetails, nil
}

type Certificate struct {
    Id             int
    RegistrationId int
    Serial         string
    Status         string
    Issued         string
    Expires        string
}

type CertificateList struct {
    BaseList
    Rows []Certificate
}

func GetCertificates(w http.ResponseWriter, r *http.Request) (CertificateList, error) {
    db, err := sql.Open(dbType, dbConn)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return CertificateList{}, err
    }

    defer db.Close()

    where := ""
    if r.URL.Query().Get("active") != "" {
        where = " WHERE cs.revokedDate='0000-00-00 00:00:00' AND cs.notAfter >= NOW()";
    } else if r.URL.Query().Get("expired") != "" {
        where = " WHERE cs.revokedDate='0000-00-00 00:00:00' AND cs.notAfter < NOW()";
    } else if r.URL.Query().Get("revoked") != "" {
        where = " WHERE cs.revokedDate<>'0000-00-00 00:00:00'";
    }

    rows, err := db.Query("SELECT c.id, c.registrationID, c.serial, CASE WHEN cs.notAfter < NOW() THEN 'expired' ELSE cs.status END AS status, c.issued, c.expires FROM certificates c JOIN certificateStatus cs ON cs.id = c.id" + where)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return CertificateList{}, err
    }

    Certificates := CertificateList{
        BaseList: BaseList{
            Title:      "Certificates",
            TableClass: "certificates_list",
            Header:     []template.HTML{"ID", "Account ID", "Serial", "Status", "Issued", "Expires"},
        },
        Rows: []Certificate{},
    }

    for rows.Next() {
        row := Certificate{}
        err = rows.Scan(&row.Id, &row.RegistrationId, &row.Serial, &row.Status, &row.Issued, &row.Expires)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return CertificateList{}, err
        }
        Certificates.Rows = append(Certificates.Rows, row)
    }

    return Certificates, nil
}

type CertificateShow struct {
    BaseShow
    Related  []BaseList
    Related2 []BaseList
}

type CertificateExtra struct {
    Id                 int
    RegistrationId     int
    Serial             string
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

func GetCertificate(w http.ResponseWriter, r *http.Request, id int, serial string) (CertificateShow, error) {
    db, err := sql.Open(dbType, dbConn)
    if err != nil {
        errorHandler(w, r, err, http.StatusInternalServerError)
        return CertificateShow{}, err
    }

    defer db.Close()

    var rows *sql.Rows
    selectWhere := "SELECT c.id, c.registrationID, c.serial, c.digest, c.issued, c.expires, cs.subscriberApproved, CASE WHEN cs.notAfter < NOW() THEN 'expired' ELSE cs.status END AS status, cs.ocspLastUpdated, cs.revokedDate, cs.revokedReason, cs.lastExpirationNagSent, cs.notAfter, cs.isExpired FROM certificates c JOIN certificateStatus cs ON cs.id = c.id WHERE "

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
            Links:      []NameValHtml{},
        },
    }

    for rows.Next() {
        row := CertificateExtra{}
        err = rows.Scan(&row.Id, &row.RegistrationId, &row.Serial, &row.Digest, &row.Issued, &row.Expires, &row.SubscriberApproved, &row.Status, &row.OCSPLastUpdate, &row.Revoked, &row.RevokedReason, &row.LastNagSent, &row.NotAfter, &row.IsExpired)
        if err != nil {
            errorHandler(w, r, err, http.StatusInternalServerError)
            return CertificateShow{}, err
        }
        CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"ID", strconv.Itoa(row.Id)})
        CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Serial", row.Serial})
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
        reasonText := ""
        switch row.RevokedReason {
        case 0:
            if row.Revoked != "0000-00-00 00:00:00" {
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
        CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Revoked Reason", strconv.Itoa(row.RevokedReason) + reasonText})
        CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Last Expiration Nag Sent", row.LastNagSent})
        CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Not After", row.NotAfter})
        v = "false"
        if row.IsExpired {
            v = "true"
        }
        CertificateDetails.Rows = append(CertificateDetails.Rows, NameValue{"Is Expired", v})

        Link := NameValHtml{"Account", template.HTML("<a href=\"" + r.Header.Get("X-Request-Base") + "/accounts/" + strconv.Itoa(row.RegistrationId) + "\">" + strconv.Itoa(row.RegistrationId) + "</a>")}
        CertificateDetails.Links = append(CertificateDetails.Links, Link)

        if row.Revoked == "0000-00-00 00:00:00" {
            revokeHtml, err := tmpls.RenderSingle("views/revoke-partial.tmpl", struct{ Serial string }{Serial: row.Serial})
            if err != nil {
                errorHandler(w, r, err, http.StatusInternalServerError)
                return CertificateShow{}, err
            }
            CertificateDetails.Extra = append(CertificateDetails.Extra, template.HTML(revokeHtml))
        }
    }

    return CertificateDetails, nil
}

