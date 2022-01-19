/*
Copyright © 2021 Yugabyte Support

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/go-logr/logr"
	"github.com/go-openapi/strfmt"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/yugabyte/yb-tools/pkg/util"
	"github.com/yugabyte/yb-tools/yb-getlogs/pkg/cmdutil"
	yugaware2 "github.com/yugabyte/yb-tools/yugaware-client/entity/yugaware"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/access_keys"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
	"golang.org/x/crypto/ssh"
)

var (
	cfgFile string

	Version = "DEV"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = RootInit()

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}

// TODO: Implement an option to install sos?
// As the centos user: /usr/bin/sudo /usr/bin/yum install sos -y
/*
	[centos@yb-dev-ianderson-gcp-n1 ~]$ sudo sosreport --batch -q

	sosreport (version 3.9)

	Your sosreport has been generated and saved in:
	  /var/tmp/sosreport-yb-dev-ianderson-gcp-n1-2021-08-12-rstsumo.tar.xz
*/

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".yb_getlogs" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".yb_getlogs")
	}

	viper.SetEnvPrefix("YW")
	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// If a config file is found, read it in.
	_ = viper.ReadInConfig()
}

func RootInit() *cobra.Command {
	globalOptions := &cmdutil.GetLogsGlobalOptions{}

	ctx := cmdutil.NewCommandContext().
		WithGlobalOptions(globalOptions)

	options := &YBGetLogsOptions{}

	cmd := &cobra.Command{
		Use:     "yb-getlogs",
		Short:   "A utility for gathering YugabyteDB logs across a Universe",
		Version: Version,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).WithOptions(options).Setup()
			if err != nil {
				return err
			}

			// Positional argument
			options.UniverseIdentifier = args[0]

			yugawareClient, err := ConnectToYugaware(ctx, ctx.Log, options)
			if err != nil {
				return err
			}

			if !yugawareClient.LoggedIn() {
				err = options.validateUsername(ctx)
				if err != nil {
					return err
				}
				err = options.validatePassword(ctx)
				if err != nil {
					return err
				}
				err = yugawareLogin(ctx, yugawareClient, options)
				if err != nil {
					return err
				}
			}

			return getlogs(ctx, yugawareClient, options)
		},
	}

	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.yb_getlogs.yaml)")
	globalOptions.AddFlags(cmd)
	options.AddFlags(cmd)

	// Top level commands
	//cmd.AddCommand(GetNodeLogs(ctx))
	return cmd
}

func ConnectToYugaware(ctx *cmdutil.YBGetlogsContext, log logr.Logger, options *YBGetLogsOptions) (*client.YugawareClient, error) {
	return client.New(ctx, log, options.Hostname).
		TLSOptions(&client.TLSOptions{
			SkipHostVerification: options.SkipHostVerification,
			CaCertPath:           options.CACert,
			CertPath:             options.ClientCert,
			KeyPath:              options.ClientKey,
		}).APIToken(options.APIToken).
		TimeoutSeconds(options.DialTimeout).
		Connect()
}

type YBGetLogsOptions struct {
	//positional argument
	UniverseIdentifier string

	Hostname             string        `mapstructure:"hostname"`
	DialTimeout          int           `mapstructure:"dialtimeout"`
	SkipHostVerification bool          `mapstructure:"skiphostverification"`
	CACert               string        `mapstructure:"cacert"`
	ClientCert           string        `mapstructure:"client_cert"`
	ClientKey            string        `mapstructure:"client_key"`
	MountPaths           []string      `mapstructure:"mountpaths"`
	CollectIntervalSince time.Duration `mapstructure:"collect_interval_since"`
	CollectIntervalUntil time.Duration `mapstructure:"collect_interval_until"`
	SSHParallelism       int           `mapstructure:"parallel"`

	APIToken string `mapstructure:"api_token"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"` // TODO: prevent logging of this field by overwriting the logr field
}

func (o *YBGetLogsOptions) AddFlags(cmd *cobra.Command) {
	// Global configuration flags
	flags := cmd.Flags()
	flags.StringVar(&o.Hostname, "hostname", "localhost:8080", "hostname of yugaware")
	flags.IntVar(&o.DialTimeout, "dialtimeout", 10, "number of seconds for dial timeouts")
	flags.BoolVar(&o.SkipHostVerification, "skiphostverification", false, "skip tls host verification")
	flags.StringVarP(&o.CACert, "cacert", "c", "", "the path to the CA certificate")
	flags.StringVar(&o.ClientCert, "client-cert", "", "the path to the client certificate")
	flags.StringVar(&o.ClientKey, "client-key", "", "the path to the client key file")
	//flags.StringVar(&logfile, "logfile", "yb-getlogs.log", "Specify a logfile name. Will be created in the current working directory if no path specified.")
	flags.StringSliceVar(&o.MountPaths, "mountpaths", []string{"/mnt/d0"}, "Specify a comma separated list of the filesystem paths where Yugabyte DB data resides")
	flags.DurationVarP(&o.CollectIntervalSince, "since", "A", time.Since(time.Unix(0, 0)), "Collect logs created since (e.g. 2d; default a long time ago). Applies only to logs with timestamped filenames.")
	flags.DurationVarP(&o.CollectIntervalUntil, "until", "B", time.Duration(0), "Collect logs created before (e.g. 1d; default now). Applies only to logs with timestamped filenames.")
	flags.IntVar(&o.SSHParallelism, "parallel", 4, "Specify the maximum number of Universe nodes to connect to in parallel")

	flags.StringVar(&o.APIToken, "api-token", "", "api token for yugaware session")
	flags.StringVar(&o.Username, "username", "", "username for yugaware login")
	flags.StringVar(&o.Password, "password", "", "password for yugaware login")
}

func (o *YBGetLogsOptions) Validate(_ *cmdutil.YBGetlogsContext) error {
	return nil
}

func getlogs(ctx *cmdutil.YBGetlogsContext, yugawareClient *client.YugawareClient, options *YBGetLogsOptions) error {
	currentUniverse, err := yugawareClient.GetUniverseByIdentifier(options.UniverseIdentifier)
	if err != nil {
		return err
	}

	if currentUniverse == nil {
		return fmt.Errorf("universe %s not found", options.UniverseIdentifier)
	}

	accessKeys, err := getAccessKeyList(ctx, yugawareClient, currentUniverse)
	if err != nil {
		return fmt.Errorf("could not obtain access keys for universe %s: %w", currentUniverse.Name, err)
	}

	privateKey, err := getPrivateKey(ctx, accessKeys[0])
	if err != nil {
		return err
	}

	// TODO: Use https://github.com/tylarb/clusterExec?
	sshUser := accessKeys[0].KeyInfo.SSHUser
	if sshUser == "" {
		sshUser = "yugabyte"
	}

	sshPort := accessKeys[0].KeyInfo.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}

	for i, node := range currentUniverse.UniverseDetails.NodeDetailsSet {
		err = getNodeLogs(ctx, privateKey, sshPort, sshUser, node, options.MountPaths)
		if err != nil {
			ctx.Log.Error(err, "failed to get node logs")
		}
		// TODO: Support connecting by hostname instead of IP, which is permitted for some providers
		// TODO: Support K8s Universes
		ipAddress := node.CloudInfo.PrivateIP

		conn, err := ssh.Dial("tcp", ipAddress+":"+strconv.Itoa(int(sshPort)), &ssh.ClientConfig{
			Config: ssh.Config{},
			User:   sshUser,
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
			ctx.Log.Error(err, "failed to dial", "host", ipAddress, "port", sshPort, "node", node)
			return err
		}
		fmt.Println("Connected!")

		_ = testSSH(ctx, conn)

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

		err = client.CopyFromRemote(ctx, targetFile, ".bashrc")
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
	return nil
}

func (o *YBGetLogsOptions) validateUsername(ctx *cmdutil.YBGetlogsContext) error {
	// TODO: Prompt for username?
	if o.Username == "" {
		return fmt.Errorf("no username specified")
	}
	ctx.Log.V(1).Info("using username", "username", o.Username)

	return nil
}

func (o *YBGetLogsOptions) validatePassword(ctx *cmdutil.YBGetlogsContext) error {
	var err error
	if o.Password == "" {
		o.Password, err = util.PasswordPrompt()
		if err != nil {
			return err
		}
		ctx.Log.V(1).Info("using password from prompt")
	}
	return nil
}

func yugawareLogin(ctx *cmdutil.YBGetlogsContext, yugawareClient *client.YugawareClient, options *YBGetLogsOptions) error {
	ctx.Log.Info("Logging into Yugaware server")

	_, err := yugawareClient.Login(&yugaware2.LoginRequest{
		Email:    options.Username,
		Password: options.Password,
	})

	return err
}

func getAccessKeyList(ctx *cmdutil.YBGetlogsContext, yugawareClient *client.YugawareClient, universe *models.UniverseResp) ([]*models.AccessKey, error) {
	providerUUID := strfmt.UUID(universe.UniverseDetails.Clusters[0].UserIntent.Provider)

	ctx.Log.V(1).Info("retrieving access key information")
	params := access_keys.NewListParams().
		WithCUUID(yugawareClient.CustomerUUID()).
		WithPUUID(providerUUID)

	accessKeys, err := yugawareClient.PlatformAPIs.AccessKeys.List(params, yugawareClient.SwaggerAuth)
	if err != nil {
		return nil, err
	}

	if len(accessKeys.GetPayload()) == 0 {
		return nil, fmt.Errorf("access key request for provider %s returned no results", providerUUID)
	}
	ctx.Log.V(1).Info("obtained access keys", "access_keys", accessKeys.GetPayload())

	return accessKeys.GetPayload(), err
}

func getPrivateKey(ctx *cmdutil.YBGetlogsContext, key *models.AccessKey) (ssh.Signer, error) {
	ctx.Log.V(1).Info("reading private key", "key", key)
	keyBytes, err := os.ReadFile(key.KeyInfo.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key %v: %s", key.KeyInfo.PrivateKey, err)
	}

	return ssh.ParsePrivateKey(keyBytes)
}

func getNodeLogs(ctx *cmdutil.YBGetlogsContext, privateKey ssh.Signer, sshPort int32, SSHUser string, node *models.NodeDetailsResp, mountPaths []string) error {
	// TODO: Support connecting by hostname instead of IP, which is permitted for some providers
	// TODO: Support K8s Universes
	ipAddress := node.CloudInfo.PrivateIP

	conn, err := ssh.Dial("tcp", ipAddress+":"+strconv.Itoa(int(sshPort)), &ssh.ClientConfig{
		Config:          ssh.Config{},
		User:            SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(privateKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  nil,
		ClientVersion:   "",
		// TODO: Do not ignore the host key
		HostKeyAlgorithms: nil,
		// TODO: Make SSH timeout configurable
		Timeout: time.Second * 30,
	})
	if err != nil {
		return fmt.Errorf("Failed to dial: %s", err)
	}
	defer conn.Close()
	fmt.Println("Connected!")

	err = testSSH(ctx, conn)
	if err != nil {
		return err
	}
	err = getFileList(ctx, conn, mountPaths)
	if err != nil {
		return err
	}

	// TODO: Write file list to temp file on node
	// TODO: Confirm free disk space on nodes before tarring
	// TODO: Tar up files listed in temp file

	// TODO: Confirm free disk space on Yugaware server before copying
	// TODO: Copy tarball to platform node
	return nil
}

func testSSH(ctx *cmdutil.YBGetlogsContext, conn *ssh.Client) error {
	// We need a new session for each SSH command
	session, err := conn.NewSession()
	if err != nil {
		fmt.Println("Failed to create session:", err)
		os.Exit(1)
	}
	defer session.Close()

	buff, err := session.CombinedOutput("/bin/date")
	if err != nil {
		ctx.Log.Error(err, "date command failed", "output", string(buff))
	}
	ctx.Log.Info("date command succeeded", "output", string(buff))
	return err
}

func getFileList(ctx *cmdutil.YBGetlogsContext, conn *ssh.Client, mountPaths []string) error {
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
		ctx.Log.Error(nil, "unused debug line to stop the linter from complaining about a TODO branch")
	}

	searchPathString := strings.Join(searchPaths, " ")

	// 🤢
	// Use Output here instead of CombinedOutput because we want to discard STDERR
	buff, err := session.Output(fmt.Sprintf("/usr/bin/find %s -name '*' %s", searchPathString, " -printf \"%p\\0%s\\n\""))
	if err != nil {
		ctx.Log.Error(err, "failed to get directory listing for mountpoints", "searchpaths", searchPathString, "output", string(buff))
	}
	ctx.Log.V(1).Info("directory listing of mountpoints", "searchpath", searchPathString, "output", string(buff))

	fileList := buildFileList(buff)
	ctx.Log.V(1).Info("initial file list", "filelist", fileList)
	fileList = filterFileList(fileList)
	ctx.Log.V(1).Info("filtered file list", "filelist", fileList)
	// TODO: Filter file list
	// TODO: Return file list
	return err
}

type LogFile struct {
	File     string
	Bytesize string
}

func buildFileList(buff []byte) []LogFile {
	var fileList []LogFile

	// Parse file list into name and size
	// We can't create a scanner from a raw byte slice, so we have to wrap it in a byte[] reader first
	scanner := bufio.NewScanner(bytes.NewReader(buff))
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), "\x00")
		fileList = append(fileList, LogFile{
			File:     s[0],
			Bytesize: s[1],
		})
	}

	return fileList
}

func filterFileList(fileList []LogFile) []LogFile {
	var filteredList []LogFile

	matchPatterns := compileMatchPatterns()

	for _, file := range fileList {
		// TODO: We can use submatch to return a date (if present), then if we hit a match, filter by date range
		// inside the conditional.
		for _, pattern := range matchPatterns {
			if pattern.MatchString(file.File) {
				filteredList = append(filteredList, file)
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
		matchPattern := regexp.MustCompile(matchString)
		matchPatterns = append(matchPatterns, matchPattern)
	}

	return matchPatterns
}

//func matchPatternByDate(pattern string, before, after) {
// TODO: This func name sucks. Naming things is hard

//}
