// Code generated by go-swagger; DO NOT EDIT.

package schedule_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
)

// DeleteScheduleV2Reader is a Reader for the DeleteScheduleV2 structure.
type DeleteScheduleV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteScheduleV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteScheduleV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteScheduleV2OK creates a DeleteScheduleV2OK with default headers values
func NewDeleteScheduleV2OK() *DeleteScheduleV2OK {
	return &DeleteScheduleV2OK{}
}

/* DeleteScheduleV2OK describes a response with status code 200, with default header values.

successful operation
*/
type DeleteScheduleV2OK struct {
	Payload *models.YBPSuccess
}

func (o *DeleteScheduleV2OK) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/customers/{cUUID}/schedules/{sUUID}/delete][%d] deleteScheduleV2OK  %+v", 200, o.Payload)
}
func (o *DeleteScheduleV2OK) GetPayload() *models.YBPSuccess {
	return o.Payload
}

func (o *DeleteScheduleV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YBPSuccess)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
