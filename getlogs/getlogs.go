package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
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

func main() {
	// TODO: Logging

	// TODO: Command line flags
	// TODO: Add debug flag
	// TODO: Add flags for specifying universe name or UUID
	// TODO: Add flags to control node list source(s) (platform postgres, YB masters, or manual)
	// TODO: Add flags for specifying individual nodes by number or name
	// TODO: Add flags for controlling time window (before / after)
	// TODO: Add flags for controlling which logs to collect (info/error/fatal)
	// TODO: Add a flag for specifying the SSH port for the nodes
	// TODO: Make it possible to set SSH ports on a node-by-node basis?
	// TODO: Add a flag for specifying the Yugaware platform server hostname
	// TODO: Add flag to list universes and node counts?

	yugawareHostname := os.Getenv("YUGAWARE_HOSTNAME")
	if yugawareHostname == "" {
		fmt.Println("No Yugaware hostname specified, falling back to localhost")
		yugawareHostname = "localhost"
	}

	email := os.Getenv("YUGAWARE_USER")
	if email == "" {
		// TODO: Prompt for Yugaware username if not supplied
		fmt.Println("No Yugaware username specified. Set the YUGAWARE_USER environment variable. Aborting.")
		os.Exit(1)
	}

	password := os.Getenv("YUGAWARE_PASS")
	if password == "" {
		// TODO: Prompt for Yugaware password if not supplied
		fmt.Println("No Yugaware username specified. Set the YUGAWARE_PASS environment variable. Aborting.")
		os.Exit(1)
	}

	// TODO: Use Swagger
	apiBaseUrl := "https://" + yugawareHostname + "/api"

	fmt.Println("Using login", email)

	// TODO: Use a flag to turn cert verification on or off
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{Transport: customTransport, Jar: jar}

	// TODO: Refactor login into a func
	_, _ = fmt.Fprintln(os.Stderr, "Logging into Yugaware server")
	loginUrl := apiBaseUrl + "/login"
	response, err := client.PostForm(loginUrl, url.Values{"email": {email}, "password": {password}})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Yugaware login failed: %v\n", err)
		os.Exit(1)
	}
	body, err := io.ReadAll(response.Body)
	var ywa YugawareAuth

	err = json.Unmarshal(body, &ywa)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to parse authentication response: %v\n", err)
		os.Exit(1)
	}
	response.Body.Close()

	// TODO: Refactor universe list retrieval into a func
	UniverseUrl := apiBaseUrl + "/customers/" + ywa.CustomerUUID + "/universes"
	_, _ = fmt.Fprintf(os.Stderr, "Retrieving Universe list from %v\n", UniverseUrl)
	response, err = client.Get(UniverseUrl)
	// TODO: Error handling

	body, err = io.ReadAll(response.Body)
	// TODO: Error handling
	//_, _ = fmt.Fprintf(os.Stderr, "Response: %s\n", body)
	response.Body.Close()

	var universes []Universe
	err = json.Unmarshal(body, &universes)
	// TODO: Error handling

	// TODO: Make this a debug statement
	_, _ = fmt.Fprintf(os.Stderr, "Universes: %+v\n", universes)

	// TODO: Bail out if there's more than one Universe and no Universe has been specified on the (non-existent) CLI
	//if len(universes) > 1 {
	// TODO: Present a list of Universes and allow the user to choose if there's more than one Universe and no Universe was specified on the CLI
	//	fmt.Println("Multiple universes detected. This script currently supports one universe per Yugaware server. Exiting.")
	//	os.Exit(1)
	//}

	// Retrieve access key info for each provider
	ProviderUUID := universes[0].UniverseDetails.Clusters[0].UserIntent.Provider
	KeyUrl := apiBaseUrl + "/customers/" + ywa.CustomerUUID + "/providers/" + ProviderUUID + "/access_keys"
	_, _ = fmt.Fprintf(os.Stderr, "Retrieving access key information from %v\n", KeyUrl)
	response, err = client.Get(KeyUrl)

	body, err = io.ReadAll(response.Body)
	response.Body.Close()

	//fmt.Fprintf(os.Stderr, "Access Key Info: %s\n", body)

	var accessKeys []AccessKey
	err = json.Unmarshal(body, &accessKeys)

	_, _ = fmt.Fprintf(os.Stderr, "Parsed access key information: %+v\n", accessKeys)

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
		_, _ = fmt.Fprintf(os.Stderr, "Connect string: %s\n", ConnectString)
	}
}
