package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// Activity is a message to be shown on the dashboard, with timestamp and css class
type Activity struct {
	Title        string
	Message      string
	Timestamp    string
	TimestampRel string
	Class        string
}

func _removeAnsiColors(line string) string {
	b := make([]byte, len(line))
	var bl int
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c >= 32 && c != 127 {
			b[bl] = c
			bl++
		}
	}
	line = string(b[:bl])
	line = strings.Replace(line, "[31m", "", -1)
	line = strings.Replace(line, "[1m", "", -1)
	line = strings.Replace(line, "[0m", "", -1)

	return line
}

func toJson(line string) (map[string]interface{}, int) {
	var obj map[string]interface{}

	idx := strings.Index(line, "JSON={")
	if idx > -1 {
		jsonStr := line[idx+5:]
		err := json.Unmarshal([]byte(jsonStr), &obj)
		if err != nil {
			fmt.Println(err)
		}
	}

	return obj, idx
}

func _parseLine(line string, loc *time.Location) Activity {
	var activity Activity

	line = _removeAnsiColors(line)

	re := regexp.MustCompile(`^.*\|\s*(\S+)(.*\:)? (\S) (\S+) (\S+) (.*)$`)
	result := re.FindStringSubmatch(line)
	if len(result) == 0 {
		return activity
	}

	activity.Class = ""
	if result[3] == "4" {
		activity.Class = "warning"
	}
	if result[3] == "3" {
		activity.Class = "error"
	}

	timestamp, err := time.ParseInLocation("2006-01-02T15:04:05.000000+00:00Z", result[1], loc)
	activity.Timestamp = ""
	activity.TimestampRel = "??"
	if err == nil {
		activity.Timestamp = timestamp.Format("02-Jan-2006 15:04:05 MST")
		activity.Timestamp = strings.Replace(activity.Timestamp, "+0000", "GMT", -1)
		activity.TimestampRel = humanize.RelTime(timestamp, time.Now(), "", "")
	}

	activity.Title = ""
	if len(result[4]) > 2 {
		tail := result[4][len(result[4])-2:]
		switch tail {
		case "ca":
			activity.Title = "Certification Agent"
		case "ra":
			activity.Title = "Registration Agent"
		case "sa":
			activity.Title = "Storage Agent"
		case "va":
			activity.Title = "Validation Agent"
		}
	}
	if activity.Title == "" {
		switch result[4] {
		case "nonce-service":
			activity.Title = "Nonce Service"
		case "boulder-publisher":
			activity.Title = "Publisher"
		case "log-validator":
			activity.Title = "Log Validator"
		case "crl-storer":
			activity.Title = "CRL Storer"
		case "crl-updater":
			activity.Title = "CRL Updater"
		case "ocsp-responder":
			activity.Title = "OCSP Responder"
		default:
			activity.Title = result[4]
		}
	}

	message := result[6]
	var idx int
	//idx := strings.Index(message, ".well-known/acme-challenge")
	//if idx > -1 {
	//	message = message[0:idx]
	//}
	if strings.Contains(message, "Checked CAA records for") {
		message = message[0:strings.Index(message, ",")]
	}

	msgJson, jsonIdx := toJson(message)

	if strings.Contains(message, "Validation result") {
		var ctyp string
		var cstat string
		if chall, ok := msgJson["Challenge"].(map[string]interface{}); ok {
			ctyp = fmt.Sprintf(" Type=%s", chall["type"])
			cstat = fmt.Sprintf(" Status=%s", chall["status"])
		}
		message = message[0:jsonIdx-1] + ":" + fmt.Sprintf(" Identifier=%s", msgJson["Identifier"]) + ctyp + cstat
	}
	if strings.Contains(message, "Signing precert") || strings.Contains(message, "Signing cert") {
		var comnm string
		var dnsnms string
		if issreq, ok := msgJson["IssuanceRequest"].(map[string]interface{}); ok {
			comnm = fmt.Sprintf(" CommonName=%s", issreq["CommonName"])
			dnsnms = fmt.Sprintf(" DNSNames=%s", issreq["DNSNames"])
		}
		message = message[0:jsonIdx-1] + ":" + comnm + dnsnms + fmt.Sprintf(" Issuer=%s", msgJson["Issuer"])
	}
	idx = strings.Index(message, " csr=[")
	if idx > -1 {
		message = message[0:idx]
	}
	idx = strings.Index(message, " certificate=[")
	if idx > -1 {
		message = message[0:idx]
	}
	idx = strings.Index(message, " precert=[")
	if idx > -1 {
		message = message[0:idx]
	}
	idx = strings.Index(message, " precertificate=[")
	if idx > -1 {
		message = message[0:idx]
	}
	if strings.Contains(message, "Certificate request - ") {
		idx = strings.Index(message, " JSON={")
		if idx > -1 {
			message = message[0:idx]
		}
	}
	if strings.Contains(message, "failed to complete security handshake") {
		activity.Class = "warning"
	}
	if strings.Contains(message, "failed to receive the preface from client") {
		activity.Class = "warning"
	}
	activity.Message = message

	return activity
}

func _parseActivity(data string) []Activity {
	var activity []Activity

	lines := strings.Split(data, "\n")

	if lines[0] == "/UTC" {
		lines[0] = "Etc/UTC"
	}
	loc, err := time.LoadLocation(lines[0])
	if err != nil {
		log.Printf("Could not determine location: %s\n", err)
		loc = time.Local
	}

	for i := len(lines) - 2; i >= 1; i-- {
		activity = append(activity, _parseLine(lines[i], loc))
	}

	return activity
}

// Component contains status info related to a LabCA component
type Component struct {
	Name         string
	Timestamp    string
	TimestampRel string
	Class        string
	LogURL       string
	LogTitle     string
	Buttons      []map[string]interface{}
}

func _parseComponents(data string) []Component {
	var components []Component

	if data[len(data)-1:] == "\n" {
		data = data[0 : len(data)-1]
	}

	parts := strings.Split(data, "|")

	if len(parts) < 6 {
		components = append(components, Component{Name: "Boulder (ACME)"})
		components = append(components, Component{Name: "Consul (Boulder)"})
		components = append(components, Component{Name: "pkilint (Boulder)"})
		components = append(components, Component{Name: "LabCA Application"})
		components = append(components, Component{Name: "LabCA Controller"})
		components = append(components, Component{Name: "MySQL Database"})
		components = append(components, Component{Name: "NGINX Webserver"})
		return components
	}

	nginx, err := time.Parse(time.RFC3339Nano, parts[0])
	nginxReal := ""
	nginxNice := "stopped"
	nginxClass := "error"
	if err == nil {
		nginxReal = nginx.Format("02-Jan-2006 15:04:05 MST")
		nginxNice = humanize.RelTime(nginx, time.Now(), "", "")
		nginxClass = ""
	}

	svc, err := time.Parse(time.RFC3339Nano, parts[1])
	svcReal := ""
	svcNice := "stopped"
	svcClass := "error"
	if err == nil {
		svcReal = svc.Format("02-Jan-2006 15:04:05 MST")
		svcNice = humanize.RelTime(svc, time.Now(), "", "")
		svcClass = ""
	}

	boulder, err := time.Parse(time.RFC3339Nano, parts[2])
	boulderReal := ""
	boulderNice := "stopped"
	boulderClass := "error"
	if err == nil {
		boulderReal = boulder.Format("02-Jan-2006 15:04:05 MST")
		boulderNice = humanize.RelTime(boulder, time.Now(), "", "")
		boulderClass = ""
	}

	labca, err := time.Parse(time.RFC3339Nano, parts[3])
	labcaReal := ""
	labcaNice := "stopped"
	labcaClass := "error"
	if err == nil {
		labcaReal = labca.Format("02-Jan-2006 15:04:05 MST")
		labcaNice = humanize.RelTime(labca, time.Now(), "", "")
		labcaClass = ""
	}

	mysql, err := time.Parse(time.RFC3339Nano, parts[4])
	mysqlReal := ""
	mysqlNice := "stopped"
	mysqlClass := "error"
	if err == nil {
		mysqlReal = mysql.Format("02-Jan-2006 15:04:05 MST")
		mysqlNice = humanize.RelTime(mysql, time.Now(), "", "")
		mysqlClass = ""
	}

	consul, err := time.Parse(time.RFC3339Nano, parts[5])
	consulReal := ""
	consulNice := "stopped"
	consulClass := "error"
	if err == nil {
		consulReal = consul.Format("02-Jan-2006 15:04:05 MST")
		consulNice = humanize.RelTime(consul, time.Now(), "", "")
		consulClass = ""
	}

	pkilint, err := time.Parse(time.RFC3339Nano, parts[6])
	pkilintReal := ""
	pkilintNice := "stopped"
	pkilintClass := "error"
	if err == nil {
		pkilintReal = pkilint.Format("02-Jan-2006 15:04:05 MST")
		pkilintNice = humanize.RelTime(pkilint, time.Now(), "", "")
		pkilintClass = ""
	}

	components = append(components, Component{Name: "Boulder (ACME)", Timestamp: boulderReal, TimestampRel: boulderNice, Class: boulderClass})
	components = append(components, Component{Name: "Consul (Boulder)", Timestamp: consulReal, TimestampRel: consulNice, Class: consulClass})
	components = append(components, Component{Name: "pkilint (Boulder)", Timestamp: pkilintReal, TimestampRel: pkilintNice, Class: pkilintClass})
	components = append(components, Component{Name: "LabCA Application", Timestamp: labcaReal, TimestampRel: labcaNice, Class: labcaClass})
	components = append(components, Component{Name: "LabCA Controller", Timestamp: svcReal, TimestampRel: svcNice, Class: svcClass})
	components = append(components, Component{Name: "MySQL Database", Timestamp: mysqlReal, TimestampRel: mysqlNice, Class: mysqlClass})
	components = append(components, Component{Name: "NGINX Webserver", Timestamp: nginxReal, TimestampRel: nginxNice, Class: nginxClass})

	return components
}

// Stat contains a statistic
type Stat struct {
	Name  string
	Hint  string
	Value string
	Class string
}

// The stats as reported by docker
type DockerStat struct {
	Name     string
	MemUsage uint64
	MemLimit uint64
	MemPerc  float64
	Pids     uint64
}

func _parseStats(data string, components []Component) []Stat {
	var stats []Stat

	if data[len(data)-1:] == "\n" {
		data = data[0 : len(data)-1]
	}

	parts := strings.Split(data, "|")

	if parts[0] == "/UTC" {
		parts[0] = "Etc/UTC"
	}
	loc, err := time.LoadLocation(parts[0])
	if err != nil {
		log.Printf("Could not determine location: %s\n", err)
		loc = time.Local
	}

	since, err := time.ParseInLocation("2006-01-02 15:04:05", parts[1], loc)
	var sinceReal string
	sinceNice := "??"
	if err == nil {
		sinceReal = since.Format("02-Jan-2006 15:04:05 MST")
		sinceNice = humanize.RelTime(since, time.Now(), "", "")
	}
	stats = append(stats, Stat{Name: "System Uptime", Hint: sinceReal, Value: sinceNice})

	if components == nil {
		return stats
	}

	stats = append(stats, Stat{Name: "Memory Limit", Value: ""})
	stats = append(stats, Stat{Name: "Memory Used", Value: ""})
	stats = append(stats, Stat{Name: "Memory Used [%]", Value: ""})

	return stats
}

func getStatsStandalone() []Stat {
	var stats []Stat

	out, err := exeCmd("cat /etc/timezone")
	if err != nil || string(out) == "/UTC\n" {
		out = []byte("Etc/UTC")
	}
	if string(out[len(out)-1:]) == "\n" {
		out = out[0 : len(out)-1]
	}
	loc, err := time.LoadLocation(string(out))
	if err != nil {
		log.Printf("Could not determine location: %s\n", err)
		loc = time.Local
	}

	out, _ = exeCmd("uptime -s")
	if string(out[len(out)-1:]) == "\n" {
		out = out[0 : len(out)-1]
	}
	since, err := time.ParseInLocation("2006-01-02 15:04:05", string(out), loc)
	var sinceReal string
	sinceNice := "??"
	if err == nil {
		sinceReal = since.Format("02-Jan-2006 15:04:05 MST")
		sinceNice = humanize.RelTime(since, time.Now(), "", "")
	}
	stats = append(stats, Stat{Name: "System Uptime", Hint: sinceReal, Value: sinceNice})

	total := "0"
	avail := "0"
	out, err = exeCmd("free -b --si")
	if err == nil {
		lines := strings.Split(string(out), "\n")
		line := ""
		for i := 0; i < len(lines); i++ {
			if strings.Contains(lines[i], ":") {
				line = lines[i]
				break
			}
		}
		re := regexp.MustCompile(`.*?\s+(\d+)\s+.*`)
		segs := re.FindStringSubmatch(line)
		if len(segs) > 1 {
			total = segs[1]
		}
		re = regexp.MustCompile(`.*\s+(\d+)$`)
		segs = re.FindStringSubmatch(line)
		if len(segs) > 1 {
			avail = segs[1]
		}
	}
	memUsed := uint64(0)
	memAvail, err := strconv.ParseUint(avail, 10, 64)
	if err != nil {
		memAvail = 0
	}
	memTotal, err := strconv.ParseUint(total, 10, 64)
	if err != nil {
		memUsed = 0
	} else {
		memUsed = memTotal - memAvail
	}

	percMem := float64(0)
	if (memUsed + memAvail) > 0 {
		percMem = float64(100) * float64(memUsed) / float64(memUsed+memAvail)
	}

	usedHuman := humanize.IBytes(memUsed)
	availHuman := humanize.IBytes(memAvail)
	percHuman := fmt.Sprintf("%s %%", humanize.FtoaWithDigits(percMem, 1))

	stats = append(stats, Stat{Name: "Memory Used", Value: usedHuman})
	class := ""
	if percMem > 75 {
		class = "warning"
	}
	if percMem > 90 {
		class = "error"
	}
	stats = append(stats, Stat{Name: "Memory Used [%]", Value: percHuman, Class: class})
	class = ""
	if memAvail < 250000000 {
		class = "warning"
	}
	if memAvail < 100000000 {
		class = "error"
	}
	stats = append(stats, Stat{Name: "Memory Available", Value: availHuman, Class: class})

	return stats
}

// What we return as json
type AjaxStat struct {
	Stat
	MemoryUsed string
	MemoryPerc string
	NumPids    int
}

func parseDockerStats(data string) []AjaxStat {
	var stats []AjaxStat

	dockerStats := []DockerStat{}
	rawStats := strings.Split(data, "\n")
	for _, rawStat := range rawStats {
		if len(rawStat) > 0 {
			elms := strings.Fields(rawStat)
			if len(elms) > 13 {
				stat := DockerStat{}
				// CONTAINER ID   NAME                CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O   PIDS
				// 817bdaec6daf   boulder-boulder-1   0.07%     255.3MiB / 1GiB     24.93%    1.18MB / 339kB    0B / 0B     158
				stat.Name = elms[1]
				x, err := humanize.ParseBigBytes(elms[3])
				if err == nil {
					stat.MemUsage = x.Uint64()
				}
				x, err = humanize.ParseBigBytes(elms[5])
				if err == nil {
					stat.MemLimit = x.Uint64()
				}
				y, err := strconv.ParseFloat(strings.Replace(elms[6], "%", "", -1), 64)
				if err == nil {
					stat.MemPerc = y
				}
				p, err := strconv.ParseUint(elms[13], 10, 64)
				if err == nil {
					stat.Pids = p
				}
				dockerStats = append(dockerStats, stat)
			}
		}
	}

	// Update the component stats
	totalMemUsage := uint64(0)
	for _, docker := range dockerStats {
		stat := AjaxStat{}
		if strings.Contains(docker.Name, "-boulder-") {
			stat.Name = "Boulder (ACME)"
		}
		if strings.Contains(docker.Name, "-bconsul-") {
			stat.Name = "Consul (Boulder)"
		}
		if strings.Contains(docker.Name, "-bpkilint-") {
			stat.Name = "pkilint (Boulder)"
		}
		if strings.Contains(docker.Name, "labca-gui-") {
			stat.Name = "LabCA Application"
		}
		if strings.Contains(docker.Name, "-control-") {
			stat.Name = "LabCA Controller"
		}
		if strings.Contains(docker.Name, "-nginx-") {
			stat.Name = "NGINX Webserver"
		}
		if strings.Contains(docker.Name, "-bmysql-") {
			stat.Name = "MySQL Database"
		}

		stat.MemoryUsed = humanize.IBytes(docker.MemUsage)
		stat.MemoryPerc = fmt.Sprintf("%s%%", humanize.FtoaWithDigits(docker.MemPerc, 1))
		stat.NumPids = int(docker.Pids)

		stats = append(stats, stat)

		totalMemUsage += docker.MemUsage
	}

	percMem := float64(0)
	if (dockerStats[0].MemLimit) > 0 {
		percMem = float64(100) * float64(totalMemUsage) / float64(dockerStats[0].MemLimit)
	}

	usedHuman := humanize.IBytes(totalMemUsage)
	limitHuman := humanize.IBytes(dockerStats[0].MemLimit)
	percHuman := fmt.Sprintf("%s%%", humanize.FtoaWithDigits(percMem, 1))

	stats = append(stats, AjaxStat{Stat: Stat{Name: "Memory Limit", Value: limitHuman}})
	stats = append(stats, AjaxStat{Stat: Stat{Name: "Memory Used", Value: usedHuman}})
	class := ""
	if percMem > 75 {
		class = "warning"
	}
	if percMem > 90 {
		class = "error"
	}
	stats = append(stats, AjaxStat{Stat: Stat{Name: "Memory Used [%]", Value: percHuman, Class: class}})

	return stats
}

// CollectDashboardData collects all data relevant for building the dashboard page
func CollectDashboardData(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	db, err := sql.Open(dbType, dbConn)
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return nil, err
	}

	defer db.Close()

	dashboardData := make(map[string]interface{})
	dashboardData["RequestBase"] = r.Header.Get("X-Request-Base")

	var rows *sql.Rows
	if viper.GetString("backend") == "step-ca" {
		rows, err = db.Query("SELECT count(*) FROM acme_accounts")

	} else {
		rows, err = db.Query("SELECT count(*) FROM registrations")
	}
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return nil, err
	}

	var dbres int
	if rows.Next() {
		err = rows.Scan(&dbres)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return nil, err
		}

		dashboardData["NumAccounts"] = dbres
	}

	if viper.GetString("backend") == "step-ca" {
		var numcerts int
		var numexpired int

		revokeds, err := stepcaGetRevokeds(db)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return nil, err
		}

		rows, err = db.Query("SELECT nvalue FROM acme_certs")
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return nil, err
		}

		var row []byte
		var dbcert stepcaCert
		for rows.Next() {
			err = rows.Scan(&row)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return nil, err
			}

			err = json.Unmarshal(row, &dbcert)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return nil, err
			}

			var block *pem.Block
			var crt *x509.Certificate
			for len(dbcert.Leaf) > 0 {
				block, dbcert.Leaf = pem.Decode(dbcert.Leaf)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return nil, errors.New("error decoding PEM: data contains block that is not a certificate")
				}
				crt, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					errorHandler(w, r, err, http.StatusInternalServerError)
					return nil, errors.Wrapf(err, "error parsing x509 certificate")
				}
			}
			if len(dbcert.Leaf) > 0 {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return nil, errors.New("error decoding PEM: unexpected data")
			}

			if time.Now().After(crt.NotAfter) {
				numexpired += 1
			} else {
				if _, found := revokeds[crt.SerialNumber.Text(10)]; !found {
					numcerts += 1
				}
			}
		}

		dashboardData["NumCerts"] = numcerts
		dashboardData["NumExpired"] = numexpired
	} else {
		rows, err = db.Query("SELECT count(*) FROM certificateStatus WHERE revokedDate='0000-00-00 00:00:00' AND notAfter >= NOW()")
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return nil, err
		}

		if rows.Next() {
			err = rows.Scan(&dbres)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return nil, err
			}

			dashboardData["NumCerts"] = dbres
		}

		rows, err = db.Query("SELECT count(*) FROM certificateStatus WHERE notAfter < NOW()")
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return nil, err
		}

		if rows.Next() {
			err = rows.Scan(&dbres)
			if err != nil {
				errorHandler(w, r, err, http.StatusInternalServerError)
				return nil, err
			}

			dashboardData["NumExpired"] = dbres
		}
	}

	if viper.GetString("backend") == "step-ca" {
		rows, err = db.Query("SELECT count(*) FROM revoked_x509_certs")
	} else {
		rows, err = db.Query("SELECT count(*) FROM certificateStatus WHERE revokedDate<>'0000-00-00 00:00:00'")
	}
	if err != nil {
		errorHandler(w, r, err, http.StatusInternalServerError)
		return nil, err
	}

	if rows.Next() {
		err = rows.Scan(&dbres)
		if err != nil {
			errorHandler(w, r, err, http.StatusInternalServerError)
			return nil, err
		}

		dashboardData["NumRevoked"] = dbres
	}

	if viper.GetString("backend") == "step-ca" {
		dashboardData["Standalone"] = true
		dashboardData["Components"] = []Component{}
		dashboardData["Stats"] = getStatsStandalone()
	} else {
		activity := getLog(w, r, "activity")
		dashboardData["Activity"] = _parseActivity(activity)

		components := _parseComponents(getLog(w, r, "components"))
		uptime := getLog(w, r, "uptime")
		dashboardData["Stats"] = _parseStats(uptime, components)
		dashboardData["Components"] = components
	}

	return dashboardData, nil
}
