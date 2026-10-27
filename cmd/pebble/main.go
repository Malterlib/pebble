package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/cmd"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

var version = "dev" // Default value, to be overridden with ldflags

type config struct {
	Pebble struct {
		ListenAddress           string
		ManagementListenAddress string
		HTTPPort                int
		TLSPort                 int
		Certificate             string
		PrivateKey              string
		OCSPResponderURL        string
		// Require External Account Binding for "newAccount" requests
		ExternalAccountBindingRequired bool
		ExternalAccountMACKeys         map[string]string
		CAAIdentities                  []string
		// Configure policies to deny certain domains
		DomainBlocklist []string
		KeyAlgorithm    string
		Profiles        map[string]ca.Profile

		RetryAfter struct {
			Authz int
			Order int
		}

		// Deprecated: use Profiles.ValidityPeriod instead
		CertificateValidityPeriod uint64
	}
}

func main() {
	configFile := flag.String(
		"config",
		"test/config/pebble-config.json",
		"File path to the Pebble configuration file")
	strictMode := flag.Bool(
		"strict",
		false,
		"Enable strict mode to test upcoming API breaking changes")
	resolverAddress := flag.String(
		"dnsserver",
		"",
		"Define a custom DNS server address (ex: 192.168.0.56:5053 or 8.8.8.8:53).")
	versionFlag := flag.Bool(
		"version",
		false,
		"Print the software version")
	flag.Parse()

	if len(flag.Args()) > 0 {
		fmt.Printf("invalid command line arguments: %s\n", strings.Join(flag.Args(), " "))
		flag.Usage()
		os.Exit(1)
	}

	if *versionFlag {
		// Print the version and exit
		fmt.Printf("Pebble version: %s\n", version)
		os.Exit(0)
	}

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *strictMode {
		fmt.Printf("Running in strict mode\n")
	}

	// Log to stdout
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
	logger.Printf("Starting Pebble ACME server")

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	alternateRoots := 0
	alternateRootsVal := os.Getenv("PEBBLE_ALTERNATE_ROOTS")
	if val, err := strconv.ParseInt(alternateRootsVal, 10, 0); err == nil && val >= 0 {
		alternateRoots = int(val)
	}

	chainLength := 1
	if val, err := strconv.ParseInt(os.Getenv("PEBBLE_CHAIN_LENGTH"), 10, 0); err == nil && val >= 0 {
		chainLength = int(val)
	}

	keyAlg := c.Pebble.KeyAlgorithm
	if keyAlg == "" {
		keyAlg = "rsa"
	}
	acceptableKeyAlgs := []string{"rsa", "ecdsa"}
	if !slices.Contains(acceptableKeyAlgs, keyAlg) {
		cmd.FailOnError(fmt.Errorf("%q is not one of %#v", keyAlg, acceptableKeyAlgs), "invalid key algorithm")
	}

	profiles := c.Pebble.Profiles
	if len(profiles) == 0 {
		profiles = map[string]ca.Profile{
			"default": {
				Description:    "The default profile",
				ValidityPeriod: 0, // Will be overridden by the CA's default
			},
		}
	}

	db := db.NewMemoryStore()
	ca := ca.New(logger, db, c.Pebble.OCSPResponderURL, keyAlg, alternateRoots, chainLength, profiles)
	va := va.New(logger, c.Pebble.HTTPPort, c.Pebble.TLSPort, *strictMode, *resolverAddress, db)

	for keyID, key := range c.Pebble.ExternalAccountMACKeys {
		err := db.AddExternalAccountKeyByID(keyID, key)
		cmd.FailOnError(err, "Failed to add key to external account bindings")
	}

	for _, domainName := range c.Pebble.DomainBlocklist {
		err := db.AddBlockedDomain(domainName)
		cmd.FailOnError(err, "Failed to add domain to block list")
	}

	if len(c.Pebble.CAAIdentities) < 1 {
		logger.Println("No CAA identities configured, using default [pebble.letsencrypt.org]")
		c.Pebble.CAAIdentities = []string{"pebble.letsencrypt.org"}
	}

	wfeImpl := wfe.New(logger, db, va, ca, c.Pebble.CAAIdentities, *strictMode, c.Pebble.ExternalAccountBindingRequired, c.Pebble.RetryAfter.Authz, c.Pebble.RetryAfter.Order)
	muxHandler := wfeImpl.Handler()

	if c.Pebble.ManagementListenAddress != "" {
		go func() {
			adminHandler := wfeImpl.ManagementHandler()
			err = http.ListenAndServeTLS(
				c.Pebble.ManagementListenAddress,
				c.Pebble.Certificate,
				c.Pebble.PrivateKey,
				adminHandler)
			cmd.FailOnError(err, "Calling ListenAndServeTLS() for admin interface")
		}()
		logger.Printf("Management interface listening on: %s\n", c.Pebble.ManagementListenAddress)
		logger.Printf("Root CA certificate available at: https://%s%s0",
			c.Pebble.ManagementListenAddress, wfe.RootCertPath)
		for i := 0; i < alternateRoots; i++ {
			logger.Printf("Alternate (%d) root CA certificate available at: https://%s%s%d",
				i+1, c.Pebble.ManagementListenAddress, wfe.RootCertPath, i+1)
		}
	} else {
		logger.Print("Management interface is disabled")
	}

	// "unix:<path>" listens on a Unix socket. Its URLs have the host
	// [UNIX:<path>], which clients such as Malterlib's connect to through the
	// socket.
	if socketPath, ok := strings.CutPrefix(c.Pebble.ListenAddress, "unix:"); ok {
		// A socket file left by an earlier run would make the listen fail
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			cmd.FailOnError(err, "Removing the old Unix socket")
		}
		listener, err := net.Listen("unix", socketPath)
		cmd.FailOnError(err, "Listening on the Unix socket")

		// The client sends the Host header of the URL it connects with, such
		// as localhost, so the socket's host is used instead, for the URLs the
		// WFE returns and the JWS url it expects. Only on this listener, the
		// management interface keeps the host of its own requests.
		host := "[UNIX:" + socketPath + "]"
		socketHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			request.Host = host
			muxHandler.ServeHTTP(response, request)
		})
		logger.Printf("Listening on: %s\n", c.Pebble.ListenAddress)
		logger.Printf("ACME directory available at: https://%s%s", host, wfe.DirectoryPath)
		server := &http.Server{Handler: socketHandler, ReadHeaderTimeout: 30 * time.Second}
		err = server.ServeTLS(listener, c.Pebble.Certificate, c.Pebble.PrivateKey)
		cmd.FailOnError(err, "Calling ServeTLS()")
		return
	}

	logger.Printf("Listening on: %s\n", c.Pebble.ListenAddress)
	logger.Printf("ACME directory available at: https://%s%s",
		c.Pebble.ListenAddress, wfe.DirectoryPath)
	err = http.ListenAndServeTLS(
		c.Pebble.ListenAddress,
		c.Pebble.Certificate,
		c.Pebble.PrivateKey,
		muxHandler)
	cmd.FailOnError(err, "Calling ListenAndServeTLS()")
}
