// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// MetricQueryParams Metrics request data
//
// swagger:model MetricQueryParams
type MetricQueryParams struct {

	// End time
	End int64 `json:"end,omitempty"`

	// Is Recharts
	IsRecharts bool `json:"isRecharts,omitempty"`

	// Metrics
	Metrics []string `json:"metrics"`

	// List of metrics with custom settings
	MetricsWithSettings []*MetricSettings `json:"metricsWithSettings"`

	// Node name
	NodeName string `json:"nodeName,omitempty"`

	// Node prefix
	NodePrefix string `json:"nodePrefix,omitempty"`

	// Start time
	// Required: true
	Start *int64 `json:"start"`
}

// Validate validates this metric query params
func (m *MetricQueryParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMetricsWithSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStart(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MetricQueryParams) validateMetricsWithSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.MetricsWithSettings) { // not required
		return nil
	}

	for i := 0; i < len(m.MetricsWithSettings); i++ {
		if swag.IsZero(m.MetricsWithSettings[i]) { // not required
			continue
		}

		if m.MetricsWithSettings[i] != nil {
			if err := m.MetricsWithSettings[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("metricsWithSettings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("metricsWithSettings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *MetricQueryParams) validateStart(formats strfmt.Registry) error {

	if err := validate.Required("start", "body", m.Start); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this metric query params based on the context it is used
func (m *MetricQueryParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetricsWithSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MetricQueryParams) contextValidateMetricsWithSettings(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.MetricsWithSettings); i++ {

		if m.MetricsWithSettings[i] != nil {
			if err := m.MetricsWithSettings[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("metricsWithSettings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("metricsWithSettings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *MetricQueryParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MetricQueryParams) UnmarshalBinary(b []byte) error {
	var res MetricQueryParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
