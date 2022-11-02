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

package create

import (
	"encoding/json"
	"fmt"

	"github.com/blang/vfs"
	"github.com/ghodss/yaml"
	"github.com/go-logr/logr"
	"github.com/go-openapi/runtime"
	. "github.com/icza/gox/gox"
	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/yugaware-client/entity/cli"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/cloud_providers"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

var longHelp = `Create a Kubernetes provider

Example template:

---
name: GKE
kubeconfig_path: /tmp/yugaware-kubeconfig-dev.yaml
service_account_name: yugabyte-platform-universe-management
image_registry: quay.io/yugabyte/yugabyte
image_pull_secret_path: /tmp/yugabyte-k8s-pull-secret-dev.yaml
regions:
  # Must be one of the following regions:
  #  [us-west us-east south-asia new-zealand eu-west us-south us-north
  #   south-east-asia japan eu-east china brazil australia]
  - code: us-east
    zone_info:
      - name: us-east1-b
        config:
          storage_class: yugaware
          kubernetes_namespace: example_namespace
          overrides: |
            nodeSelector:
              cloud.google.com/gke-nodepool: yugabyte-us-east1-b
          # Override global kubeconfig for this namespace
          kubeconfig_path: /tmp/yugabyte-useast1-b-kubeconfig.yaml
      - name: us-east1-c
        config:
          storage_class: yugaware
          overrides: |
            nodeSelector:
              cloud.google.com/gke-nodepool: yugabyte-us-east1-c
      - name: us-east1-d
        config:
          storage_class: yugaware
          overrides: |
            nodeSelector:
              cloud.google.com/gke-nodepool: yugabyte-us-east1-
                `

func KubernetesProviderCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "kubernetes_provider --filename <file>",
		Short: "Create a Kubernetes provider",
		Long:  longHelp,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := ctx.WithCmd(cmd).Setup()
			if err != nil {
				return err
			}

			providerConfig, err := readKubernetesConfiguration(ctx.Fs, ctx.Log, configPath)
			if err != nil {
				return err
			}

			return createKubernetesProvider(ctx, providerConfig)
		},
	}

	cmd.Flags().StringVarP(&configPath, "filename", "f", "", "Path to kubernetes configuration")

	if err := cmd.MarkFlagRequired("filename"); err != nil {
		panic(err)
	}

	return cmd
}

func readKubernetesConfiguration(fs vfs.Filesystem, log logr.Logger, config string) (*cli.KubernetesProvider, error) {
	log.V(1).Info("reading kubernetes provider configuration", "path", config)
	configBytesYAML, err := vfs.ReadFile(fs, config)
	if err != nil {
		return nil, err
	}
	configJSONBytes, err := yaml.YAMLToJSON(configBytesYAML)
	if err != nil {
		return nil, err
	}
	kubernetesConfig := &cli.KubernetesProvider{}
	err = json.Unmarshal(configJSONBytes, kubernetesConfig)
	if err != nil {
		return nil, err
	}
	log.V(1).Info("read kubernetes config", config, kubernetesConfig)

	return kubernetesConfig, nil
}

func createKubernetesProvider(ctx *cmdutil.YWClientContext, config *cli.KubernetesProvider) error {
	log := ctx.Log
	ywc := ctx.Client
	log.V(1).Info("fetching providers")
	providers, err := ywc.PlatformAPIs.CloudProviders.GetListOfProviders(&cloud_providers.GetListOfProvidersParams{
		CUUID:      ywc.CustomerUUID(),
		Context:    ctx,
		HTTPClient: ywc.Session(),
	}, ywc.SwaggerAuth, func(*runtime.ClientOperation) {})
	if err != nil {
		return err
	}

	if kubernetesProviderAlreadyConfigured(providers.GetPayload(), config.Name, "kubernetes") {
		log.Info("provider is already configured")
		return nil
	}

	err = registerKubernetesProvider(ctx, config)
	if err != nil {
		return err
	}

	return nil
}

func registerKubernetesProvider(ctx *cmdutil.YWClientContext, provider *cli.KubernetesProvider) error {
	log := ctx.Log
	ywc := ctx.Client

	log = log.WithValues("name", provider.Name, "provider", "kubernetes")
	request, err := makeKubernetesProviderRequest(ctx.Fs, log, ywc, provider)
	if err != nil {
		return err
	}

	log.Info("registering provider")
	response, err := ywc.PlatformAPIs.CloudProviders.CreateProviders(request, ywc.SwaggerAuth)
	if err != nil {
		log.Error(err, "failed to register provider")
		return err
	}
	log.Info("registered provider", "response", response.GetPayload())

	return nil
}

func kubernetesProviderAlreadyConfigured(providers []*models.Provider, name, code string) bool {
	for _, provider := range providers {
		if provider.Name == name &&
			provider.Code == code {
			return true
		}
	}
	return false
}

func makeKubernetesProviderRequest(fs vfs.Filesystem, log logr.Logger, ywclient *client.YugawareClient, provider *cli.KubernetesProvider) (*cloud_providers.CreateProvidersParams, error) {
	if provider.ImageRegistry == "" {
		provider.ImageRegistry = "quay.io/yugabyte/yugabyte"
	}

	log.Info("reading kubeconfig", "path", provider.KubeconfigPath)
	kubeconfig, err := vfs.ReadFile(fs, provider.KubeconfigPath)
	if err != nil {
		log.Error(err, "unable to read kubeconfig")
		return nil, err
	}

	// Open the pull secret if available
	pullSecret, pullSecretName, pullSecretFilename := getPullSecret(fs, log, provider.ImagePullSecretPath)

	var regions []*models.Region
	for _, region := range provider.Regions {
		kubeRegion, err := lookupGkeRegion(region.Code)
		if err != nil {
			return nil, err
		}

		for _, zone := range region.ZoneInfo {
			kubeZone, err := getKubernetesZone(fs, log, zone, kubeconfig)
			if err != nil {
				return nil, err
			}

			kubeRegion.Zones = append(kubeRegion.Zones, kubeZone)
		}

		regions = append(regions, kubeRegion)
	}

	request := cloud_providers.NewCreateProvidersParams().
		WithCUUID(ywclient.CustomerUUID()).
		WithCreateProviderRequest(&models.Provider{
			Code: "kubernetes",
			Config: map[string]string{
				"KUBECONFIG_PROVIDER":               "gke",
				"KUBECONFIG_SERVICE_ACCOUNT":        provider.ServiceAccountName,
				"KUBECONFIG_IMAGE_REGISTRY":         provider.ImageRegistry,
				"KUBECONFIG_IMAGE_PULL_SECRET_NAME": pullSecretName,
				"KUBECONFIG_PULL_SECRET_NAME":       pullSecretFilename,
				"KUBECONFIG_PULL_SECRET_CONTENT":    string(pullSecret),
			},
			Name:    provider.Name,
			Regions: regions,
		})

	return request, nil
}

func getKubernetesZone(fs vfs.Filesystem, log logr.Logger, info cli.ZoneInfo, kubeconfig []byte) (*models.AvailabilityZone, error) {
	log = log.WithValues("zone", info.Name)
	if info.Config.KubeconfigPath != "" {
		log.Info("reading overridden kubeconfig", "path", info.Config.KubeconfigPath)
		kubeconfigOverride, err := vfs.ReadFile(fs, info.Config.KubeconfigPath)
		if err != nil {
			log.Error(err, "unable to read kubeconfig", "path", info.Config.KubeconfigPath)
			return &models.AvailabilityZone{}, err
		}
		kubeconfig = kubeconfigOverride
	}

	zone := &models.AvailabilityZone{
		Code: info.Name,
		Name: NewString(info.Name),
		Config: map[string]string{
			"OVERRIDES":          info.Config.Overrides,
			"KUBECONFIG_NAME":    info.Name + "-kubeconfig",
			"KUBECONFIG_CONTENT": string(kubeconfig),
		},
	}

	if info.Config.StorageClass != "" {
		zone.Config["STORAGE_CLASS"] = info.Config.StorageClass
	}

	if info.Config.KubernetesNamespace != "" {
		zone.Config["KUBENAMESPACE"] = info.Config.KubernetesNamespace
	}

	log.V(1).Info("generated zone", "zone", &zone)
	return zone, nil
}

func lookupGkeRegion(regionCode string) (*models.Region, error) {
	RegionData := map[string]*models.Region{
		"us-west":         {Code: "us-west", Name: "US West", Latitude: 37, Longitude: -121},
		"us-east":         {Code: "us-east", Name: "US East", Latitude: 36.8, Longitude: -79},
		"us-south":        {Code: "us-south", Name: "US South", Latitude: 28, Longitude: -99},
		"us-north":        {Code: "us-north", Name: "US North", Latitude: 48, Longitude: -118},
		"south-asia":      {Code: "south-asia", Name: "South Asia", Latitude: 18.4, Longitude: 78.4},
		"south-east-asia": {Code: "south-east-asia", Name: "SE Asia", Latitude: 14, Longitude: 101},
		"new-zealand":     {Code: "new-zealand", Name: "New Zealand", Latitude: -43, Longitude: 171},
		"japan":           {Code: "japan", Name: "Japan", Latitude: 36, Longitude: 139},
		"eu-west":         {Code: "eu-west", Name: "EU West", Latitude: 48, Longitude: 3},
		"eu-east":         {Code: "eu-east", Name: "EU East", Latitude: 46, Longitude: 25},
		"china":           {Code: "china", Name: "China", Latitude: 31.2, Longitude: 121.5},
		"brazil":          {Code: "brazil", Name: "Brazil", Latitude: -22, Longitude: -43},
		"australia":       {Code: "australia", Name: "Australia", Latitude: -29, Longitude: 148},
	}
	if _, ok := RegionData[regionCode]; !ok {

		var validRegions []string
		for region := range RegionData {
			validRegions = append(validRegions, region)
		}
		return &models.Region{}, fmt.Errorf("invalid region: %s must be one of: %v", regionCode, validRegions)
	}
	return RegionData[regionCode], nil
}

func getPullSecret(fs vfs.Filesystem, log logr.Logger, secretPath string) ([]byte, string, string) {
	if secretPath == "" {
		log.V(1).Info("no secret provided")
		return []byte{}, "", ""
	}

	log.Info("reading pull secret", "path", secretPath)
	pullSecret, err := vfs.ReadFile(fs, secretPath)
	if err != nil {
		log.Error(err, "unable to read image pull secret")
		return []byte{}, "", ""
	}

	log.Info("decoding pull secret")

	type Secretmeta struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	secretMeta := &Secretmeta{}
	err = yaml.Unmarshal(pullSecret, secretMeta)
	if err != nil {
		log.Error(err, "unable to unmarshal pull secret")
		return []byte{}, "", ""
	}

	return pullSecret, secretMeta.Metadata.Name, secretMeta.Metadata.Name + ".yaml"
}
