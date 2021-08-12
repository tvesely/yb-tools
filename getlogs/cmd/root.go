package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"time"
)

var (
	debugEnabled bool

	logfile string

	yugawareHostname string
	yugawareUsername string
	yugawarePassword string

	disableCertCheck bool
	httpTimeout      time.Duration

	rootCmd = &cobra.Command{
		Use:     "yb-getlogs",
		Short:   "A utility for gathering YugabyteDB logs across a Universe",
		Version: "0.0.1",
		Run: func(cmd *cobra.Command, args []string) {
			getlogs()
		},
	}
)

type YugawareAuth struct {
	AuthToken    string `json:"authToken"`
	CustomerUUID string `json:"customerUUID"`
	UserUUID     string `json:"userUUID"`
}

type NodeDetails struct {
	NodeIdx   int    `json:"nodeIdx"`
	NodeName  string `json:"nodeName"`
	CloudInfo struct {
		PrivateIp string `json:"private_ip"`
		PublicIp  string `json:"public_ip"`
	} `json:"cloudInfo"`
	IsMaster  bool `json:"isMaster"`
	Master    bool `json:"master"`
	IsTserver bool `json:"isTserver"`
	Tserver   bool `json:"tserver"`
}

type Cluster struct {
	Uuid       string `json:"uui"`
	UserIntent struct {
		Provider string `json:"provider"`
	} `json:"userIntent"`
}

type Universe struct {
	UniverseUUID string `json:"universeUUID"`
	Name         string `json:"name"`
	Resources    struct {
		NumNodes int `json:"numNodes"`
	} `json:"resources"`
	UniverseDetails struct {
		NodeDetailsSet []NodeDetails `json:"nodeDetailsSet"`
		Clusters       []Cluster     `json:"clusters"`
	} `json:"universeDetails"`
}

type AccessKey struct {
	//IdKey struct {
	//	KeyCode string `json:"keyCode"`
	//	ProviderUUID string `json:"providerUUID"`
	//} `json:"idKey"`
	KeyInfo struct {
		PublicKey              string `json:"publicKey"`
		PrivateKey             string `json:"privateKey"`
		SshUser                string `json:"sshUser"`
		SshPort                int    `json:"sshPort"`
		PasswordlessSudoAccess bool   `json:"passwordlessSudoAccess"`
	} `json:"keyInfo"`
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&debugEnabled, "debug", false, "Enable debug logging")

	// TODO: Implement logging
	//rootCmd.PersistentFlags().StringVar(&logfile, "logfile", "yb-getlogs.log", "Specify a logfile name. Will be created in the current working directory if no path specified.")

	rootCmd.PersistentFlags().StringVarP(&yugawareHostname, "hostname", "H", "", "Hostname or IP address of Yugaware platform node (default \"localhost\")")
	rootCmd.PersistentFlags().StringVarP(&yugawareUsername, "username", "U", "", "Yugaware login name (email)")
	rootCmd.PersistentFlags().StringVarP(&yugawarePassword, "password", "P", "", "Yugaware password")

	rootCmd.PersistentFlags().BoolVar(&disableCertCheck, "no-check-certificate", false, "Disable strict certificate checking when connecting to Yugaware platform")
	// TODO: Validation (must be a positive integer
	rootCmd.PersistentFlags().DurationVar(&httpTimeout, "http-timeout", time.Second*30, "Specify a timeout for HTTP connections to the Yugaware server. Accepts a duration with unit (e.g. 30s). Set to 0 to disable.")
}

func getlogs() {
	dbg("Enter")

	validateHostname()
	validateUsername()
	validatePassword()
	oldMain()

	dbg("Leave")
}

func getFunctionName() string {
	pc := make([]uintptr, 15)
	n := runtime.Callers(3, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	return frame.Function
}

func dbg(msg string) {
	if debugEnabled {
		fmt.Fprintln(os.Stderr, getFunctionName(), msg)
	}
}

func validateHostname() {
	dbg("Enter")

	if yugawareHostname != "" {
		dbg("Found hostname '" + yugawareHostname + "' on the CLI")
	} else {
		dbg("No hostname specified on the CLI")
		dbg("Checking for hostname in YUGAWARE_HOSTNAME environment variable")
		yugawareHostname = os.Getenv("YUGAWARE_HOSTNAME")
	}
	if yugawareHostname == "" {
		fmt.Println("No hostname specified. Falling back to 'localhost'.")
		yugawareHostname = "localhost"
	}
	dbg("Using hostname '" + yugawareHostname + "'")

	dbg("Leave")
}

func validateUsername() {
	dbg("Enter")

	if yugawareUsername != "" {
		dbg("Found username '" + yugawareUsername + "' on the CLI")
	} else {
		dbg("No username specified on the CLI")
		dbg("Checking for username in YUGAWARE_USER environment variable")
		yugawareUsername = os.Getenv("YUGAWARE_USER")
	}
	if yugawareUsername == "" {
		dbg("Checking for username in YUGAWARE_USERNAME environment variable")
		yugawareUsername = os.Getenv("YUGAWARE_USERNAME")
	}
	// TODO: Prompt for username?
	if yugawareUsername == "" {
		dbg("Failed to find username")
		fmt.Println("No --username specified and no YUGAWARE_USER environment variable set. Specify a username and try again.")
		os.Exit(1)
	}
	dbg("Using username '" + yugawareUsername + "'")

	dbg("Leave")
}

func validatePassword() {
	dbg("Enter")
	if yugawarePassword != "" {
		dbg("Using password specified on the CLI")
	} else {
		dbg("No password specified on the CLI")
		dbg("Checking for password in YUGAWARE_PASS environment variable")
		yugawarePassword = os.Getenv("YUGAWARE_PASS")
	}
	if yugawarePassword == "" {
		dbg("Checking for password in YUGAWARE_PASSWORD environment variable")
		yugawarePassword = os.Getenv("YUGAWARE_PASSWORD")
	}
	if yugawarePassword == "" {
		dbg("Asking the user for the password")
		fmt.Print("Please enter the password for Yugaware user '" + yugawareUsername + "': ")
		passwordBytes, err := terminal.ReadPassword(0)
		if err != nil {
			fmt.Println("Failed to read password from terminal.")
		}
		fmt.Println("")
		yugawarePassword = string(passwordBytes)
	}
	if yugawarePassword == "" {
		dbg("Failed to find password")
		fmt.Println("No --password specified and no YUGAWARE_PASS environment variable set. Specify a username and try again.")
		os.Exit(1)
	}
	dbg("Found a password (but not recording it in the logs)")

	dbg("Leave")
}

func oldMain() {
	dbg("Enter")
	// TODO: Use Swagger
	apiBaseUrl := "https://" + yugawareHostname + "/api"

	fmt.Println("Using login", yugawareUsername)

	var client *http.Client

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create cookie jar for HTTP client: %v\n", err)
	}

	transport := http.DefaultTransport.(*http.Transport)
	if disableCertCheck {
		transport = http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client = &http.Client{Jar: jar, Timeout: httpTimeout, Transport: transport}

	// TODO: Refactor login into a func
	_, _ = fmt.Fprintln(os.Stderr, "Logging into Yugaware server")
	loginUrl := apiBaseUrl + "/login"
	response, err := client.PostForm(loginUrl, url.Values{"email": {yugawareUsername}, "password": {yugawarePassword}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Yugaware login failed: %v\n", err)
		os.Exit(1)
	}
	body, err := io.ReadAll(response.Body)
	// TODO: Error handling
	dbg(fmt.Sprintf("Raw login response: %s", body))
	var ywa YugawareAuth

	err = json.Unmarshal(body, &ywa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse authentication response: %v\n", err)
		os.Exit(1)
	}
	response.Body.Close()

	// TODO: Refactor universe list retrieval into a func
	UniverseUrl := apiBaseUrl + "/customers/" + ywa.CustomerUUID + "/universes"
	fmt.Println("Retrieving Universe list")
	dbg(fmt.Sprintf("Retrieving Universe list from %v", UniverseUrl))
	response, err = client.Get(UniverseUrl)
	// TODO: Error handling

	body, err = io.ReadAll(response.Body)
	// TODO: Error handling
	//fmt.Fprintf(os.Stderr, "Response: %s\n", body)
	response.Body.Close()

	var universes []Universe
	err = json.Unmarshal(body, &universes)
	// TODO: Error handling

	// TODO: Make this a debug statement
	dbg(fmt.Sprintf("Universes: %+v", universes))

	// TODO: Bail out if there's more than one Universe and no Universe has been specified on the (non-existent) CLI
	//if len(universes) > 1 {
	// TODO: Present a list of Universes and allow the user to choose if there's more than one Universe and no Universe was specified on the CLI
	//	fmt.Println("Multiple universes detected. This script currently supports one universe per Yugaware server. Exiting.")
	//	os.Exit(1)
	//}

	fmt.Println("Found", len(universes), "Universes. Currently this utility retrieves logs from the first Universe in the list.")
	currentUniverse := universes[0]
	fmt.Println("Retrieving logs from Universe '"+currentUniverse.Name+"' with UUID", currentUniverse.UniverseUUID)

	// Retrieve access key info for each provider
	ProviderUUID := currentUniverse.UniverseDetails.Clusters[0].UserIntent.Provider
	KeyUrl := apiBaseUrl + "/customers/" + ywa.CustomerUUID + "/providers/" + ProviderUUID + "/access_keys"
	dbg(fmt.Sprintf("Retrieving access key information from %v\n", KeyUrl))
	response, err = client.Get(KeyUrl)

	body, err = io.ReadAll(response.Body)
	response.Body.Close()

	//fmt.Fprintf(os.Stderr, "Access Key Info: %s\n", body)

	var accessKeys []AccessKey
	err = json.Unmarshal(body, &accessKeys)

	dbg(fmt.Sprintf("Parsed access key information: %+v\n", accessKeys))

	SshUser := accessKeys[0].KeyInfo.SshUser
	if SshUser == "" {
		SshUser = "yugabyte"
	}
	SshPort := accessKeys[0].KeyInfo.SshPort
	if SshPort == 0 {
		SshPort = 22
	}

	for _, node := range universes[0].UniverseDetails.NodeDetailsSet {
		IpAddress := node.CloudInfo.PrivateIp

		// TODO: Check if we can read the private key file(s) before attempting to use it / them
		// TODO: Factor out binary names
		ConnectString := "/usr/bin/sudo /usr/bin/ssh -i " + accessKeys[0].KeyInfo.PrivateKey + " -ostricthostkeychecking=no" + " -p " + strconv.Itoa(SshPort) + " " + SshUser + "@" + IpAddress
		fmt.Fprintf(os.Stderr, "Connect string: %s\n", ConnectString)
	}
	dbg("Leave")
}
