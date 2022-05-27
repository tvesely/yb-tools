// Code generated by go-swagger; DO NOT EDIT.

package certificate_info

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
)

// NewEditCertificateParams creates a new EditCertificateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewEditCertificateParams() *EditCertificateParams {
	return &EditCertificateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewEditCertificateParamsWithTimeout creates a new EditCertificateParams object
// with the ability to set a timeout on a request.
func NewEditCertificateParamsWithTimeout(timeout time.Duration) *EditCertificateParams {
	return &EditCertificateParams{
		timeout: timeout,
	}
}

// NewEditCertificateParamsWithContext creates a new EditCertificateParams object
// with the ability to set a context for a request.
func NewEditCertificateParamsWithContext(ctx context.Context) *EditCertificateParams {
	return &EditCertificateParams{
		Context: ctx,
	}
}

// NewEditCertificateParamsWithHTTPClient creates a new EditCertificateParams object
// with the ability to set a custom HTTPClient for a request.
func NewEditCertificateParamsWithHTTPClient(client *http.Client) *EditCertificateParams {
	return &EditCertificateParams{
		HTTPClient: client,
	}
}

/* EditCertificateParams contains all the parameters to send to the API endpoint
   for the edit certificate operation.

   Typically these are written to a http.Request.
*/
type EditCertificateParams struct {

	// CUUID.
	//
	// Format: uuid
	CUUID strfmt.UUID

	// RUUID.
	//
	// Format: uuid
	RUUID strfmt.UUID

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the edit certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EditCertificateParams) WithDefaults() *EditCertificateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the edit certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EditCertificateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the edit certificate params
func (o *EditCertificateParams) WithTimeout(timeout time.Duration) *EditCertificateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the edit certificate params
func (o *EditCertificateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the edit certificate params
func (o *EditCertificateParams) WithContext(ctx context.Context) *EditCertificateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the edit certificate params
func (o *EditCertificateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the edit certificate params
func (o *EditCertificateParams) WithHTTPClient(client *http.Client) *EditCertificateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the edit certificate params
func (o *EditCertificateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCUUID adds the cUUID to the edit certificate params
func (o *EditCertificateParams) WithCUUID(cUUID strfmt.UUID) *EditCertificateParams {
	o.SetCUUID(cUUID)
	return o
}

// SetCUUID adds the cUuid to the edit certificate params
func (o *EditCertificateParams) SetCUUID(cUUID strfmt.UUID) {
	o.CUUID = cUUID
}

// WithRUUID adds the rUUID to the edit certificate params
func (o *EditCertificateParams) WithRUUID(rUUID strfmt.UUID) *EditCertificateParams {
	o.SetRUUID(rUUID)
	return o
}

// SetRUUID adds the rUuid to the edit certificate params
func (o *EditCertificateParams) SetRUUID(rUUID strfmt.UUID) {
	o.RUUID = rUUID
}

// WriteToRequest writes these params to a swagger request
func (o *EditCertificateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param cUUID
	if err := r.SetPathParam("cUUID", o.CUUID.String()); err != nil {
		return err
	}

	// path param rUUID
	if err := r.SetPathParam("rUUID", o.RUUID.String()); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
