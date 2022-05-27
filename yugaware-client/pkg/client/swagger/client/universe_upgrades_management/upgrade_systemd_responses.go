// Code generated by go-swagger; DO NOT EDIT.

package universe_upgrades_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
)

// UpgradeSystemdReader is a Reader for the UpgradeSystemd structure.
type UpgradeSystemdReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpgradeSystemdReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpgradeSystemdOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpgradeSystemdOK creates a UpgradeSystemdOK with default headers values
func NewUpgradeSystemdOK() *UpgradeSystemdOK {
	return &UpgradeSystemdOK{}
}

/* UpgradeSystemdOK describes a response with status code 200, with default header values.

successful operation
*/
type UpgradeSystemdOK struct {
	Payload *models.YBPTask
}

func (o *UpgradeSystemdOK) Error() string {
	return fmt.Sprintf("[POST /api/v1/customers/{cUUID}/universes/{uniUUID}/upgrade/systemd][%d] upgradeSystemdOK  %+v", 200, o.Payload)
}
func (o *UpgradeSystemdOK) GetPayload() *models.YBPTask {
	return o.Payload
}

func (o *UpgradeSystemdOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YBPTask)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
