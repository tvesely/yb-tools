package yugaware

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
