package main

import (
	"flag"
	"fmt"
	netmail "net/mail"
	"os"
	"time"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bmail "github.com/letsencrypt/boulder/mail"
)

const usageString = `
usage:
mail-tester --config <path> <recipient>

args:
  config    File path to the configuration file for this service
  recipient Email address to send an email to
`

type config struct {
	Mailer struct {
		cmd.ServiceConfig
		cmd.DBConfig
		cmd.SMTPConfig

		From    string
		Subject string

		DNSTries     int
		DNSResolvers []string

		Features map[string]bool
	}

	Syslog cmd.SyslogConfig

	Common struct {
		DNSResolver               string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool
	}
}

func main() {
	usage := func() {
		fmt.Fprintf(os.Stderr, usageString)
		os.Exit(1)
	}

	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	args := flag.Args()
	recipient := args[0]

	if len(os.Args) <= 3 || *configFile == "" {
		usage()
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Mailer.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.Mailer.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	dnsTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
	cmd.FailOnError(err, "Couldn't parse DNS timeout")
	dnsTries := c.Mailer.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	var resolver bdns.Client
	if len(c.Common.DNSResolver) != 0 {
		c.Mailer.DNSResolvers = append(c.Mailer.DNSResolvers, c.Common.DNSResolver)
	}
	if !c.Common.DNSAllowLoopbackAddresses {
		r := bdns.New(
			dnsTimeout,
			c.Mailer.DNSResolvers,
			scope,
			clk,
			dnsTries,
			logger)
		resolver = r
	} else {
		r := bdns.NewTest(dnsTimeout, c.Mailer.DNSResolvers, scope, clk, dnsTries, logger)
		resolver = r
	}

	fromAddress, err := netmail.ParseAddress(c.Mailer.From)
	cmd.FailOnError(err, fmt.Sprintf("Could not parse from address: %s", c.Mailer.From))

	smtpPassword, err := c.Mailer.PasswordConfig.Pass()
	cmd.FailOnError(err, "Failed to load SMTP password")
	mailClient := bmail.New(
		c.Mailer.Server,
		c.Mailer.Port,
		c.Mailer.Username,
		smtpPassword,
		nil,
		resolver,
		*fromAddress,
		logger,
		scope,
		1*time.Second,
		5*60*time.Second)

	mailClient.Connect()
	defer mailClient.Close()

	recipients := []string{}
	recipients = append(recipients, recipient)

	err = mailClient.SendMail(recipients, "Test Email from LabCA", "Test sending email from the LabCA server")
	cmd.FailOnError(err, "mail-tester has failed")
}
