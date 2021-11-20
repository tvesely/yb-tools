package cmd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/bramvdbogaerde/go-scp"
	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/yb-getlogs/entity/yugaware"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/term"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	Version = "DEV"

	debugEnabled bool

	logfile string

	yugawareHostname string
	yugawarePort     string
	yugawareUsername string
	yugawarePassword string

	disableHttps     bool
	disableCertCheck bool
	httpTimeout      time.Duration

	httpClient *http.Client

	apiBaseUrl string
	ywa        yugaware.YugawareAuth

	universeId      string
	universes       []yugaware.Universe
	currentUniverse yugaware.Universe

	accessKeys []yugaware.AccessKey

	mountPaths []string

	sshParallelism int

	rootCmd = &cobra.Command{
		Use:     "yb-getlogs",
		Short:   "A utility for gathering YugabyteDB logs across a Universe",
		Version: Version,
		Run: func(cmd *cobra.Command, args []string) {
			getlogs()
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&debugEnabled, "debug", false, "Enable debug logging")

	// TODO: Implement logging
	rootCmd.PersistentFlags().StringVar(&logfile, "logfile", "yb-getlogs.log", "Specify a logfile name. Will be created in the current working directory if no path specified. Not implemented yet.")

	rootCmd.PersistentFlags().StringVarP(&yugawareHostname, "hostname", "H", "", "Hostname or IP address of the Yugaware platform server (default \"localhost\")")
	// TODO: Allow environment variables for this flag, as with other connectivity flags
	rootCmd.PersistentFlags().StringVarP(&yugawarePort, "port", "p", "", "Port number to use for connecting to the Yugaware platform (optional)")
	rootCmd.PersistentFlags().StringVarP(&yugawareUsername, "username", "U", "", "Yugaware login name (email)")
	rootCmd.PersistentFlags().StringVarP(&yugawarePassword, "password", "P", "", "Yugaware password")

	rootCmd.PersistentFlags().BoolVar(&disableHttps, "http-insecure", false, "Use http instead of https when connecting to the Yugaware platform server (not recommended)")
	rootCmd.PersistentFlags().BoolVar(&disableCertCheck, "no-check-certificate", false, "Disable strict certificate checking when connecting to the Yugaware platform server")
	rootCmd.PersistentFlags().DurationVar(&httpTimeout, "http-timeout", time.Second*30, "Specify a timeout for HTTP connections to the Yugaware platform server. Accepts a duration with unit (e.g. 30s). Set to 0 to disable.")

	rootCmd.PersistentFlags().StringVar(&universeId, "universe", "", "Specify the name or UUID of a Universe from which to collect the logs")

	rootCmd.PersistentFlags().StringSliceVar(&mountPaths, "mountpaths", []string{"/mnt/d0"}, "Specify a comma separated list of the filesystem paths where Yugabyte DB data resides")

	rootCmd.PersistentFlags().IntVar(&sshParallelism, "parallel", 4, "Specify the number of Universe nodes to connect to in parallel")

	// TODO: Implement an option to install sos?
	// As the centos user: /usr/bin/sudo /usr/bin/yum install sos -y
	/*
		[centos@yb-dev-ianderson-gcp-n1 ~]$ sudo sosreport --batch -q

		sosreport (version 3.9)

		Your sosreport has been generated and saved in:
		  /var/tmp/sosreport-yb-dev-ianderson-gcp-n1-2021-08-12-rstsumo.tar.xz
	*/
}

func getlogs() {
	dbg("Enter")

	// TODO: Mask passwords in this output
	dbg(fmt.Sprintf("Called using the following command line: %v", os.Args))

	validateHostname()
	validateUsername()
	validatePassword()
	configHttpClient()
	yugawareLogin()
	universes = getUniverseList()
	// TODO: Put this selection logic into a func
	if len(universes) == 0 {
		fmt.Println("No universes found. Exiting.")
		os.Exit(0)
	} else if len(universes) == 1 {
		currentUniverse = universes[0]
	} else {
		if universeId == "" {
			// TODO: Present a list of Universes and allow the user to choose if there's more than one Universe and no Universe was specified on the CLI
			fmt.Println("Multiple universes found and no universe identifier (name or UUID) specified. Exiting.")
			os.Exit(1)
		}
		var err error
		// TODO: Is this making a copy of the struct? That may be sub-optimal.
		currentUniverse, err = getUniverseById(universeId)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	var err error
	accessKeys, err = getAccessKeys(currentUniverse)
	if err != nil {
		fmt.Printf("Failed to connect to universe %s: %s\n", universeId, err)
		os.Exit(1)
	}
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

// TODO: DRY the next three funcs out
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
		passwordBytes, err := term.ReadPassword(0)
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

func configHttpClient() {
	dbg("Enter")

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create cookie jar for HTTP client: %v\n", err)
	}

	transport := http.DefaultTransport.(*http.Transport)
	if disableCertCheck {
		transport = http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	httpClient = &http.Client{Jar: jar, Timeout: httpTimeout, Transport: transport}

	var protocolString string
	if disableHttps {
		protocolString = "http://"
	} else {
		protocolString = "https://"
	}

	portString := ""
	if yugawarePort != "" {
		portString = ":" + yugawarePort
	}
	apiBaseUrl = protocolString + yugawareHostname + portString + "/api"

	dbg("Leave")
}

func yugawareLogin() {
	dbg("Enter")

	// TODO: Factor this API wrapper out into a separate module
	fmt.Println("Logging into Yugaware server")

	loginUrl := apiBaseUrl + "/login"
	response, err := httpClient.PostForm(loginUrl, url.Values{"email": {yugawareUsername}, "password": {yugawarePassword}})
	// TODO: Figure out why I added a TODO here
	if err != nil {
		fmt.Fprintf(os.Stderr, "Yugaware login failed: %v\n", err)
		os.Exit(1)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse login response body: %v\n", err)
	}
	dbg(fmt.Sprintf("Raw login response: %s", body))
	if response.StatusCode == 401 {
		fmt.Fprintf(os.Stderr, "Yugaware login failed: %s\n", body)
		os.Exit(1)
	}

	err = json.Unmarshal(body, &ywa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse authentication response: %v\n", err)
		os.Exit(1)
	}

	dbg("Leave")
}

func getUniverseList() []yugaware.Universe {
	dbg("Enter")

	UniverseUrl := apiBaseUrl + "/customers/" + ywa.CustomerUUID + "/universes"

	fmt.Println("Retrieving Universe list")
	dbg(fmt.Sprintf("Retrieving Universe list from %v", UniverseUrl))

	response, err := httpClient.Get(UniverseUrl)
	if err != nil {
		fmt.Printf("Failed to retrieve Universe list: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Failed to read Universe list: %v", err)
	}
	dbg(fmt.Sprintf("Raw universe JSON: %s", body))

	var universeList []yugaware.Universe

	err = json.Unmarshal(body, &universeList)
	if err != nil {
		fmt.Printf("Failed to parse Universe list: %v", err)
	}

	dbg(fmt.Sprintf("Universes: %+v", universeList))

	dbg("Leave")
	return universeList
}

func getUniverseById(universeId string) (yugaware.Universe, error) {
	dbg("Enter")

	// This may produce unexpected results if some idiot has set a Universe name that is a valid UUID for another
	// Universe. Don't do this.
	for _, universe := range universes {
		if universe.UniverseUUID == universeId || universe.Name == universeId {
			return universe, nil
		}
	}

	dbg("Leave")
	return yugaware.Universe{}, fmt.Errorf("could not find Universe with identifier '%s'", universeId)
}

func getAccessKeys(universe yugaware.Universe) ([]yugaware.AccessKey, error) {
	dbg("Enter")

	var keys []yugaware.AccessKey

	ProviderUUID := universe.UniverseDetails.Clusters[0].UserIntent.Provider
	KeyUrl := apiBaseUrl + "/customers/" + ywa.CustomerUUID + "/providers/" + ProviderUUID + "/access_keys"
	dbg(fmt.Sprintf("Retrieving access key information from %v", KeyUrl))
	response, err := httpClient.Get(KeyUrl)
	if err != nil {
		return keys, err
	}

	var body []byte
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return keys, err
	}

	//fmt.Fprintf(os.Stderr, "Access Key Info: %s\n", body)

	err = json.Unmarshal(body, &keys)
	if err != nil {
		return keys, err
	}

	dbg(fmt.Sprintf("Parsed access key information: %+v", keys))
	err = nil
	if len(keys) == 0 {
		err = fmt.Errorf("no access keys found in Universe info")
	}

	dbg("Leave")
	return keys, err
}

func oldMain() {
	dbg("Enter")
	// TODO: Use Swagger?

	// TODO: Use https://github.com/tylarb/clusterExec?
	SshUser := accessKeys[0].KeyInfo.SshUser
	if SshUser == "" {
		SshUser = "yugabyte"
	}
	SshPort := accessKeys[0].KeyInfo.SshPort
	if SshPort == 0 {
		SshPort = 22
	}

	privateKey, err := readPrivateKey(accessKeys[0].KeyInfo.PrivateKey)
	if err != nil {
		fmt.Printf("Failed to read private key %v: %s", accessKeys[0].KeyInfo.PrivateKey, err)
		os.Exit(1)
	}

	for i, node := range currentUniverse.UniverseDetails.NodeDetailsSet {
		getNodeLogs(privateKey, SshPort, SshUser, node)
		// TODO: Support connecting by hostname instead of IP, which is permitted for some providers
		IpAddress := node.CloudInfo.PrivateIp

		conn, err := ssh.Dial("tcp", IpAddress+":"+strconv.Itoa(SshPort), &ssh.ClientConfig{
			Config: ssh.Config{},
			User:   SshUser,
			Auth:   []ssh.AuthMethod{ssh.PublicKeys(privateKey)},
			// TODO: Do not ignore the host key
			HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
			BannerCallback:    nil,
			ClientVersion:     "",
			HostKeyAlgorithms: nil,
			// TODO: Make SSH timeout configurable
			Timeout: time.Second * 30,
		})
		if err != nil {
			fmt.Printf("Failed to dial: %s", err)
			os.Exit(1)
		}
		fmt.Println("Connected!")

		_ = testSsh(conn)

		// TODO: Parallelize with goroutines
		// TODO: Use waitgroup to wait for all go routines to finish

		wg := &sync.WaitGroup{}

		// Do this for each goroutine directly before calling the goroutine
		wg.Add(1)

		go func(wg *sync.WaitGroup) {
			// At end of goroutine
			wg.Done()
		}(wg)

		// After all goroutines have been called:
		// Waits for waitgroup to be done (Add => increments, Done => decrements)
		wg.Wait()

		// TODO: Ensure license information for go-scp is included before shipping
		client, err := scp.NewClientBySSH(conn)
		if err != nil {
			fmt.Println("Error creating new SSH session from existing connection", err)
			os.Exit(1)
		}

		targetFile, err := os.Create("./testfile" + strconv.Itoa(i))
		if err != nil {
			fmt.Println("Error creating local file for writing", err)
			os.Exit(1)
		}

		err = client.CopyFromRemote(targetFile, ".bashrc")
		if err != nil {
			fmt.Println("Error copying from remote file", err)
			os.Exit(1)
		}

		err = targetFile.Close()
		if err != nil {
			fmt.Println("Error closing local file", err)
			os.Exit(1)
		}

		// TODO: Refactor so we can use defer
		err = conn.Close()
		if err != nil {
			fmt.Println("Failed to close connection:", err)
			os.Exit(1)
		}

	}
	dbg("Leave")
}

func readPrivateKey(keyFile string) (ssh.Signer, error) {
	dbg("Enter")
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	dbg("Leave")
	return ssh.ParsePrivateKey(keyBytes)
}

func getNodeLogs(PrivateKey ssh.Signer, SshPort int, SshUser string, node yugaware.NodeDetails) {
	IpAddress := node.CloudInfo.PrivateIp

	conn, err := ssh.Dial("tcp", IpAddress+":"+strconv.Itoa(SshPort), &ssh.ClientConfig{
		Config:          ssh.Config{},
		User:            SshUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(PrivateKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  nil,
		ClientVersion:   "",
		// TODO: Do not ignore the host key
		HostKeyAlgorithms: nil,
		// TODO: Make SSH timeout configurable
		Timeout: time.Second * 30,
	})
	if err != nil {
		fmt.Printf("Failed to dial: %s", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("Connected!")

	_ = testSsh(conn)
	_ = getFileList(conn)
	// TODO: Write file list to temp file on node
	// TODO: Confirm free disk space on nodes before tarring
	// TODO: Tar up files listed in temp file

	// TODO: Confirm free disk space on Yugaware server before copying
	// TODO: Copy tarball to platform node
}

func testSsh(conn *ssh.Client) error {
	dbg("Enter")
	// We need a new session for each SSH command
	session, err := conn.NewSession()
	if err != nil {
		fmt.Println("Failed to create session:", err)
		os.Exit(1)
	}
	defer session.Close()

	buff, err := session.CombinedOutput("/bin/date")
	if err == nil {
		dbg(fmt.Sprintf("Output of date: %s", buff))
	}
	dbg("Leave")
	return err
}

func getFileList(conn *ssh.Client) error {
	session, err := conn.NewSession()
	if err != nil {
		fmt.Println("Failed to create session:", err)
		return err
	}
	defer session.Close()

	searchPaths := make([]string, len(mountPaths))
	copy(searchPaths, mountPaths)
	for n := range searchPaths {
		searchPaths[n] += "/yb-data"
	}
	searchPaths = append(searchPaths, "/var/log")
	//homeDir := os.Getenv("HOME")
	// TODO: Make this dynamic again (but we don't want this to be /home/centos!)
	homeDir := "/home/yugabyte"
	if homeDir != "" {
		searchPaths = append(searchPaths, homeDir)
	} else {
		// TODO: Warn that we won't be able to collect the server.conf flag files
		dbg("Unused debug line to stop the linter from complaining about a TODO branch")
	}

	searchPathString := strings.Join(searchPaths, " ")

	// 🤢
	// Use Output here instead of CombinedOutput because we want to discard STDERR
	buff, err := session.Output(fmt.Sprintf("/usr/bin/find %s -name '*' %s", searchPathString, " -printf \"%p\\0%s\\n\""))
	if err != nil {
		fmt.Printf("Failed to get directory listing for mountpoints %s: %v", searchPathString, err)
	}
	dbg(fmt.Sprintf("Directory listing of mountpoints %s:\n%s", searchPathString, buff))

	fileList := buildFileList(buff)
	dbg(fmt.Sprintf("Initial file List: %v", fileList))
	fileList = filterFileList(fileList)
	dbg(fmt.Sprintf("Filtered file List: %v", fileList))
	// TODO: Filter file list
	// TODO: Return file list
	return err
}

func buildFileList(buff []byte) []yugaware.LogFile {
	var fileList []yugaware.LogFile

	// Parse file list into name and size
	// We can't create a scanner from a raw byte slice, so we have to wrap it in a byte[] reader first
	scanner := bufio.NewScanner(bytes.NewReader(buff))
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), "\x00")
		fileList = append(fileList, yugaware.LogFile{
			File:     s[0],
			Bytesize: s[1],
		})
		dbg(fmt.Sprintln("File:", s[0], "Size:", s[1]))
	}

	return fileList
}

func filterFileList(fileList []yugaware.LogFile) []yugaware.LogFile {
	var filteredList []yugaware.LogFile

	matchPatterns := compileMatchPatterns()

	for _, file := range fileList {
		// TODO: We can use submatch to return a date (if present), then if we hit a match, filter by date range
		// inside the conditional.
		for _, pattern := range matchPatterns {
			if pattern.MatchString(file.File) {
				dbg(fmt.Sprintf("File %s matched pattern %s\n", file.File, pattern.String()))
				filteredList = append(filteredList, file)
			} else {
				dbg(fmt.Sprintf("File %s did not match pattern %s\n", file.File, pattern.String()))
			}
		}
		// TODO: Add matching and date filtering for date filtered files
	}

	return filteredList
}

func compileMatchPatterns() []*regexp.Regexp {
	var matchPatterns []*regexp.Regexp

	var matchStrings []string

	matchStrings = append(matchStrings, "^/var/log/messages")
	matchStrings = append(matchStrings, "yb-data/(?:master|tserver)/(?:consensus|tablet)-meta")
	matchStrings = append(matchStrings, "yb-data/(?:master|tserver)/instance$")
	// No backreferences?! Denied...
	matchStrings = append(matchStrings, "yb-data/(?:master|tserver)/logs/yb-(?:master|tserver)\\.pid$")
	matchStrings = append(matchStrings, "yb-data/(?:master|tserver)/logs/yb-(?:master|tserver).*FATAL")
	matchStrings = append(matchStrings, "(?:master|tserver)/conf/server.conf")

	for _, matchString := range matchStrings {
		matchPattern, err := regexp.Compile(matchString)
		if err != nil {
			// TODO: Error handling
			dbg("Unused debug line to stop the linter from complaining about a TODO branch")
		}
		matchPatterns = append(matchPatterns, matchPattern)
	}

	return matchPatterns
}

//func matchPatternByDate(pattern string, before, after) {
// TODO: This func name sucks. Naming things is hard

//}
