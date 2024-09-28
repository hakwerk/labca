package notmain

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	netmail "net/mail"
	"os"
	"time"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	bconfig "github.com/letsencrypt/boulder/config"
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
		DebugAddr string
		DB        cmd.DBConfig
		cmd.SMTPConfig

		From    string
		Subject string

		CertLimit int
		NagTimes  []string
		// How much earlier (than configured nag intervals) to
		// send reminders, to account for the expected delay
		// before the next expiration-mailer invocation.
		NagCheckInterval string
		// Path to a text/template email template
		EmailTemplate string

		Frequency bconfig.Duration

		TLS       cmd.TLSConfig
		SAService *cmd.GRPCClientConfig

		DNSTries                  int
		DNSStaticResolvers        []string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool

		// Path to a file containing a list of trusted root certificates for use
		// during the SMTP connection (as opposed to the gRPC connections).
		SMTPTrustedRootFile string

		Features features.Config
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
	usage := func() {
		fmt.Fprintf(os.Stderr, usageString)
		os.Exit(1)
	}

	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if len(os.Args) <= 3 || *configFile == "" {
		usage()
	}

	args := flag.Args()
	recipient := args[0]

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	features.Set(c.Mailer.Features)

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.Mailer.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	tlsConfig, err := c.Mailer.TLS.Load(scope)
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	dnsTimeout, err := time.ParseDuration(c.Mailer.DNSTimeout)
	cmd.FailOnError(err, "Couldn't parse DNS timeout")
	dnsTries := c.Mailer.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	var resolver bdns.Client
	servers, err := bdns.NewStaticProvider(c.Mailer.DNSStaticResolvers)
	cmd.FailOnError(err, "Couldn't start static DNS server resolver")
	if !c.Mailer.DNSAllowLoopbackAddresses {
		r := bdns.New(
			dnsTimeout,
			servers,
			scope,
			clk,
			dnsTries,
			logger,
			tlsConfig)
		resolver = r
	} else {
		r := bdns.NewTest(dnsTimeout, servers, scope, clk, dnsTries, logger, tlsConfig)
		resolver = r
	}

	var smtpRoots *x509.CertPool
	smtpSkipVerify := false
	if c.Mailer.SMTPTrustedRootFile == "InsecureSkipVerify" {
		smtpSkipVerify = true
	} else if c.Mailer.SMTPTrustedRootFile != "" {
		pem, err := os.ReadFile(c.Mailer.SMTPTrustedRootFile)
		cmd.FailOnError(err, "Loading trusted roots file")
		smtpRoots = x509.NewCertPool()
		if !smtpRoots.AppendCertsFromPEM(pem) {
			cmd.FailOnError(nil, "Failed to parse root certs PEM")
		}
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
		smtpRoots,
		smtpSkipVerify,
		resolver,
		*fromAddress,
		logger,
		scope,
		1*time.Second,
		5*60*time.Second)

	conn, err := mailClient.Connect()
	cmd.FailOnError(err, "mail-tester failed to connect")
	defer conn.Close()

	recipients := []string{}
	recipients = append(recipients, recipient)

	err = conn.SendMail(recipients, "Test Email from LabCA", "Test sending email from the LabCA server")
	cmd.FailOnError(err, "mail-tester has failed")
}

func init() {
	cmd.RegisterCommand("mail-tester", main, &cmd.ConfigValidator{Config: &config{}})
}
