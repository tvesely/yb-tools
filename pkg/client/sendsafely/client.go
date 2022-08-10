package sendsafely

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/yugabyte/yb-tools/pkg/client/sendsafely/oapi"
)

type SendSafely struct {
	apiSecret string
	apiKey    string

	dropzoneID string

	hostname string

	Api oapi.ClientWithResponsesInterface
}

func New(hostname string) *SendSafely {
	return &SendSafely{
		hostname: hostname,
	}
}

func (c *SendSafely) WithAuth(apiSecret, apiKey string) *SendSafely {
	c.apiSecret = apiSecret
	c.apiKey = apiKey

	return c
}

func (c *SendSafely) WithAnonymousDropzone(dropzoneID string) *SendSafely {
	c.dropzoneID = dropzoneID

	return c
}

func (c *SendSafely) Complete() (*SendSafely, error) {
	var err error
	c.Api, err = c.setupOpenAPIClient()

	return c, err
}

func (c *SendSafely) setupOpenAPIClient(opts ...oapi.ClientOption) (oapi.ClientWithResponsesInterface, error) {
	opts = append(opts, oapi.WithRequestEditorFn(c.generateAuthFunction()))

	return oapi.NewClientWithResponses(c.hostname, opts...)
}

func (c *SendSafely) useAuth() bool {
	return c.apiKey != "" && c.apiSecret != ""
}

func (c *SendSafely) useAnonymousDropzone() bool {
	if c.useAuth() {
		return false
	}
	return c.dropzoneID != ""
}

func (c *SendSafely) setAnonymousDropzoneHeaders(req *http.Request) error {
	req.URL.Path = "/drop-zone/v2.0" + req.URL.Path

	req.Header.Set("ss-api-key", c.dropzoneID)
	req.Header.Set("ss-request-api", "DROP_ZONE")

	req.Header.Del("ss-request-timestamp")
	req.Header.Del("ss-request-signature")

	return nil
}

func (c *SendSafely) generateAuthFunction() oapi.RequestEditorFn {
	tzFormat := `2006-01-02T15:04:05-0700`

	return func(ctx context.Context, req *http.Request) error {
		if c.useAnonymousDropzone() {
			return c.setAnonymousDropzoneHeaders(req)
		}

		req.URL.Path = "/api/v2.0" + req.URL.Path

		if !c.useAuth() {
			return nil
		}

		timestamp := time.Now()

		var body []byte
		if req.Body != nil {
			b, err := req.GetBody()
			if err != nil {
				return err
			}
			body, err = io.ReadAll(b)
			if err != nil {
				return err
			}
		}

		h := hmac.New(sha256.New, []byte(c.apiSecret))

		h.Write([]byte(c.apiKey))
		h.Write([]byte(req.URL.Path))
		h.Write([]byte(timestamp.Format(tzFormat)))
		requestSignature := hex.EncodeToString(h.Sum(body))

		req.Header.Set("ss-api-key", c.apiKey)
		req.Header.Set("ss-request-timestamp", timestamp.Format(tzFormat))
		req.Header.Set("ss-request-signature", requestSignature)

		return nil
	}
}
