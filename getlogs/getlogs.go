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
)

type YugawareAuth struct {
	AuthToken    string `json:"authToken"`
	CustomerUUID string `json:"customerUUID"`
	UserUUID     string `json:"userUUID"`
}

func main() {
	// TODO: Command line flags
	// TODO: Add debug flag
	// TODO: Add flags for specifying universe name or UUID
	// TODO: Add flags to control node list source(s) (platform postgres, YB masters, or manual)
	// TODO: Add flags for specifying individual nodes by number and by name
	// TODO: Add flags for controlling time window (before / after)
	// TODO: Add flags for controlling which logs to collect (info/error/fatal)
	// TODO: Add a flag for specifying the SSH port for the nodes
	// TODO: Make it possible to set SSH ports on a node-by-node basis?
	// TODO: Add a flag for specifying the Yugaware platform server hostname

	// TODO: Log into Yugaware and retrieve the Universe list

	// TODO: Bail out if there's more than one Universe and no Universe has been specified on the (non-existent) CLI
	// TODO: Present a list of Universes and allow the user to choose if there's more than one Universe and no Universe was specified on the CLI

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

	apiBaseUrl := "https://" + yugawareHostname + "/api"

	fmt.Println("Using login", email)

	// TODO: Use a flag to turn cert verification on or off
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{Transport: customTransport, Jar: jar}

	// TODO: Refactor login into a func
	_, _ = fmt.Fprintln(os.Stderr, "Logging into Yugaware server")
	// TODO: Break down URLs further since we know hostname + /api/ will always be the same
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
	UniverseUri := apiBaseUrl + "/customers/" + ywa.CustomerUUID + "/universes"
	_, _ = fmt.Fprintf(os.Stderr, "Retrieving Universe list from %v\n", UniverseUri)
	response, err = client.Get(UniverseUri)

	defer response.Body.Close()
	body, err = io.ReadAll(response.Body)
	//_, _ = fmt.Fprintf(os.Stderr, "Response: %s\n", body)
}
