package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
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

func _parseLine(line string, loc *time.Location) Activity {
	var activity Activity

	line = _removeAnsiColors(line)

	re := regexp.MustCompile("^.*\\|\\s*(\\S)(\\S+) (\\S+) (\\S+) (.*)$")
	result := re.FindStringSubmatch(line)

	activity.Class = ""
	if result[1] == "W" {
		activity.Class = "warning"
	}
	if result[1] == "E" {
		activity.Class = "error"
	}

	timestamp, err := time.ParseInLocation("060102150405", result[2], loc)
	activity.Timestamp = ""
	activity.TimestampRel = "??"
	if err == nil {
		activity.Timestamp = timestamp.Format("02-Jan-2006 15:04:05 MST")
		activity.Timestamp = strings.Replace(activity.Timestamp, "+0000", "GMT", -1)
		activity.TimestampRel = humanize.RelTime(timestamp, time.Now(), "", "")
	}

	tail := result[3][len(result[3])-2:]
	activity.Title = ""
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

	message := result[5]
	idx := strings.Index(message, ".well-known/acme-challenge")
	if idx > -1 {
		message = message[0:idx]
	}
	if strings.Index(message, "Checked CAA records for") > -1 {
		message = message[0:strings.Index(message, ",")]
	}
	if strings.Index(message, "Validation result") > -1 {
		message = message[0:30]
	}
	idx = strings.Index(message, " csr=[")
	if idx > -1 {
		message = message[0:idx]
	}
	idx = strings.Index(message, " certificate=[")
	if idx > -1 {
		message = message[0:idx]
	}
	if strings.Index(message, "Certificate request - ") > -1 {
		idx = strings.Index(message, " JSON={")
		if idx > -1 {
			message = message[0:idx]
		}
	}
	activity.Message = message

	return activity
}

func _parseActivity(data string) []Activity {
	var activity []Activity

	lines := strings.Split(data, "\n")

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

	loc, err := time.LoadLocation(parts[0])
	if err != nil {
		log.Printf("Could not determine location: %s\n", err)
		loc = time.Local
	}

	nginx, err := time.ParseInLocation("Jan _2 15:04:05 2006", parts[1], loc)
	nginxReal := ""
	nginxNice := "stopped"
	nginxClass := "error"
	if err == nil {
		nginxReal = nginx.Format("02-Jan-2006 15:04:05 MST")
		nginxNice = humanize.RelTime(nginx, time.Now(), "", "")
		nginxClass = ""
	}

	svc, err := time.ParseInLocation("Jan _2 15:04:05 2006", parts[2], loc)
	svcReal := ""
	svcNice := "stopped"
	svcClass := "error"
	if err == nil {
		svcReal = svc.Format("02-Jan-2006 15:04:05 MST")
		svcNice = humanize.RelTime(svc, time.Now(), "", "")
		svcClass = ""
	}

	boulder, err := time.ParseInLocation("Jan _2 15:04:05 2006", parts[3], loc)
	boulderReal := ""
	boulderNice := "stopped"
	boulderClass := "error"
	if err == nil {
		boulderReal = boulder.Format("02-Jan-2006 15:04:05 MST")
		boulderNice = humanize.RelTime(boulder, time.Now(), "", "")
		boulderClass = ""
	}

	labca, err := time.ParseInLocation("Jan _2 15:04:05 2006", parts[4], loc)
	labcaReal := ""
	labcaNice := "stopped"
	labcaClass := "error"
	if err == nil {
		labcaReal = labca.Format("02-Jan-2006 15:04:05 MST")
		labcaNice = humanize.RelTime(labca, time.Now(), "", "")
		labcaClass = ""
	}

	components = append(components, Component{Name: "NGINX Webserver", Timestamp: nginxReal, TimestampRel: nginxNice, Class: nginxClass})
	components = append(components, Component{Name: "Host Service", Timestamp: svcReal, TimestampRel: svcNice, Class: svcClass})
	components = append(components, Component{Name: "Boulder (ACME)", Timestamp: boulderReal, TimestampRel: boulderNice, Class: boulderClass})
	components = append(components, Component{Name: "LabCA Application", Timestamp: labcaReal, TimestampRel: labcaNice, Class: labcaClass})

	return components
}

// Stat contains a statistic
type Stat struct {
	Name  string
	Hint  string
	Value string
	Class string
}

func _parseStats(data string) []Stat {
	var stats []Stat

	if data[len(data)-1:] == "\n" {
		data = data[0 : len(data)-1]
	}

	parts := strings.Split(data, "|")

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

	numProcs, err := strconv.Atoi(parts[2])
	if err != nil {
		numProcs = 0
	}
	stats = append(stats, Stat{Name: "Process Count", Value: strconv.Itoa(numProcs)})

	memUsed, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil {
		memUsed = 0
	}
	memAvail, err := strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		memAvail = 0
	}

	percMem := float64(0)
	if (memUsed + memAvail) > 0 {
		percMem = float64(100) * float64(memUsed) / float64(memUsed+memAvail)
	}

	usedHuman := humanize.IBytes(memUsed)
	availHuman := humanize.IBytes(memAvail)
	percHuman := fmt.Sprintf("%s %%", humanize.FtoaWithDigits(percMem, 1))

	class := ""
	if percMem > 75 {
		class = "warning"
	}
	if percMem > 90 {
		class = "error"
	}
	stats = append(stats, Stat{Name: "Memory Usage", Value: percHuman, Class: class})
	stats = append(stats, Stat{Name: "Memory Used", Value: usedHuman})
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

	rows, err := db.Query("SELECT count(*) FROM registrations")
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

	rows, err = db.Query("SELECT count(*) FROM certificateStatus WHERE revokedDate='0000-00-00 00:00:00' AND notAfter < NOW()")
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

	rows, err = db.Query("SELECT count(*) FROM certificateStatus WHERE revokedDate<>'0000-00-00 00:00:00'")
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

	activity := getLog(w, r, "activity")
	dashboardData["Activity"] = _parseActivity(activity)

	components := getLog(w, r, "components")
	dashboardData["Components"] = _parseComponents(components)

	stats := getLog(w, r, "stats")
	dashboardData["Stats"] = _parseStats(stats)

	return dashboardData, nil
}
