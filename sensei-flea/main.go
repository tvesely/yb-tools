package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/yugabyte/yb-tools/pkg/client/sendsafely"
	"github.com/yugabyte/yb-tools/pkg/client/sendsafely/oapi"
)

func mustLookupEnv(key string) string {
	if val, present := os.LookupEnv(key); !present {
		panic("could not find environment key: " + key)
	} else {
		return val
	}
}

func main() {
	_ = mustLookupEnv("SS_API_SECRET")
	_ = mustLookupEnv("SS_API_KEY")
	ssDropzone := mustLookupEnv("SS_DROPZONE")

	c, err := sendsafely.New("https://demo.sendsafely.com/").WithAnonymousDropzone(ssDropzone).Complete()
	if err != nil {
		panic("could not get client")
	}

	resp, err := c.Api.CreatePackageWithResponse(context.Background(), &oapi.CreatePackageParams{}, oapi.CreatePackageJSONRequestBody{})
	if err != nil {
		panic(fmt.Sprintf("returned error %s", err))
	}

	r, err := json.MarshalIndent(resp.JSON200, "", " ")
	if err != nil {
		panic(fmt.Sprintf("marshal json returned error %s", err))
	}

	fmt.Printf("%s\n", r)
}
