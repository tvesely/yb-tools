// Code generated by go-swagger; DO NOT EDIT.

package session_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
)

// NewRegisterCustomerParams creates a new RegisterCustomerParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRegisterCustomerParams() *RegisterCustomerParams {
	return &RegisterCustomerParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRegisterCustomerParamsWithTimeout creates a new RegisterCustomerParams object
// with the ability to set a timeout on a request.
func NewRegisterCustomerParamsWithTimeout(timeout time.Duration) *RegisterCustomerParams {
	return &RegisterCustomerParams{
		timeout: timeout,
	}
}

// NewRegisterCustomerParamsWithContext creates a new RegisterCustomerParams object
// with the ability to set a context for a request.
func NewRegisterCustomerParamsWithContext(ctx context.Context) *RegisterCustomerParams {
	return &RegisterCustomerParams{
		Context: ctx,
	}
}

// NewRegisterCustomerParamsWithHTTPClient creates a new RegisterCustomerParams object
// with the ability to set a custom HTTPClient for a request.
func NewRegisterCustomerParamsWithHTTPClient(client *http.Client) *RegisterCustomerParams {
	return &RegisterCustomerParams{
		HTTPClient: client,
	}
}

/* RegisterCustomerParams contains all the parameters to send to the API endpoint
   for the register customer operation.

   Typically these are written to a http.Request.
*/
type RegisterCustomerParams struct {

	// CustomerRegisterFormData.
	CustomerRegisterFormData *models.CustomerRegisterFormData

	// GenerateAPIToken.
	GenerateAPIToken *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the register customer params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RegisterCustomerParams) WithDefaults() *RegisterCustomerParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the register customer params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RegisterCustomerParams) SetDefaults() {
	var (
		generateAPITokenDefault = bool(false)
	)

	val := RegisterCustomerParams{
		GenerateAPIToken: &generateAPITokenDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the register customer params
func (o *RegisterCustomerParams) WithTimeout(timeout time.Duration) *RegisterCustomerParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the register customer params
func (o *RegisterCustomerParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the register customer params
func (o *RegisterCustomerParams) WithContext(ctx context.Context) *RegisterCustomerParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the register customer params
func (o *RegisterCustomerParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the register customer params
func (o *RegisterCustomerParams) WithHTTPClient(client *http.Client) *RegisterCustomerParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the register customer params
func (o *RegisterCustomerParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCustomerRegisterFormData adds the customerRegisterFormData to the register customer params
func (o *RegisterCustomerParams) WithCustomerRegisterFormData(customerRegisterFormData *models.CustomerRegisterFormData) *RegisterCustomerParams {
	o.SetCustomerRegisterFormData(customerRegisterFormData)
	return o
}

// SetCustomerRegisterFormData adds the customerRegisterFormData to the register customer params
func (o *RegisterCustomerParams) SetCustomerRegisterFormData(customerRegisterFormData *models.CustomerRegisterFormData) {
	o.CustomerRegisterFormData = customerRegisterFormData
}

// WithGenerateAPIToken adds the generateAPIToken to the register customer params
func (o *RegisterCustomerParams) WithGenerateAPIToken(generateAPIToken *bool) *RegisterCustomerParams {
	o.SetGenerateAPIToken(generateAPIToken)
	return o
}

// SetGenerateAPIToken adds the generateApiToken to the register customer params
func (o *RegisterCustomerParams) SetGenerateAPIToken(generateAPIToken *bool) {
	o.GenerateAPIToken = generateAPIToken
}

// WriteToRequest writes these params to a swagger request
func (o *RegisterCustomerParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.CustomerRegisterFormData != nil {
		if err := r.SetBodyParam(o.CustomerRegisterFormData); err != nil {
			return err
		}
	}

	if o.GenerateAPIToken != nil {

		// query param generateApiToken
		var qrGenerateAPIToken bool

		if o.GenerateAPIToken != nil {
			qrGenerateAPIToken = *o.GenerateAPIToken
		}
		qGenerateAPIToken := swag.FormatBool(qrGenerateAPIToken)
		if qGenerateAPIToken != "" {

			if err := r.SetQueryParam("generateApiToken", qGenerateAPIToken); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
