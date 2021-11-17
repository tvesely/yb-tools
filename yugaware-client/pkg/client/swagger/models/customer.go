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

// Customer Customer information, including associated universes
//
// swagger:model Customer
type Customer struct {

	// Customer code
	// Example: admin
	// Required: true
	Code *string `json:"code"`

	// Creation time
	// Example: 2021-06-17T15:00:05-0400
	// Read Only: true
	// Format: date-time
	CreationDate strfmt.DateTime `json:"creationDate,omitempty"`

	// Customer ID
	// Example: 1
	// Read Only: true
	CustomerID int64 `json:"customerId,omitempty"`

	// Name of customer
	// Example: sridhar
	// Required: true
	Name *string `json:"name"`

	// Universe UUIDs
	// Example: [c3595ca7-68a3-47f0-b1b2-1725886d5ed5, 9e0bb733-556c-4935-83dd-6b742a2c32e6]
	// Read Only: true
	// Unique: true
	UniverseUUIDs []strfmt.UUID `json:"universeUUIDs"`

	// Customer UUID
	// Read Only: true
	// Format: uuid
	UUID strfmt.UUID `json:"uuid,omitempty"`
}

// Validate validates this customer
func (m *Customer) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUniverseUUIDs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUUID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Customer) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *Customer) validateCreationDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CreationDate) { // not required
		return nil
	}

	if err := validate.FormatOf("creationDate", "body", "date-time", m.CreationDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Customer) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *Customer) validateUniverseUUIDs(formats strfmt.Registry) error {
	if swag.IsZero(m.UniverseUUIDs) { // not required
		return nil
	}

	if err := validate.UniqueItems("universeUUIDs", "body", m.UniverseUUIDs); err != nil {
		return err
	}

	for i := 0; i < len(m.UniverseUUIDs); i++ {

		if err := validate.FormatOf("universeUUIDs"+"."+strconv.Itoa(i), "body", "uuid", m.UniverseUUIDs[i].String(), formats); err != nil {
			return err
		}

	}

	return nil
}

func (m *Customer) validateUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.UUID) { // not required
		return nil
	}

	if err := validate.FormatOf("uuid", "body", "uuid", m.UUID.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this customer based on the context it is used
func (m *Customer) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreationDate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUniverseUUIDs(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUUID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Customer) contextValidateCreationDate(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "creationDate", "body", strfmt.DateTime(m.CreationDate)); err != nil {
		return err
	}

	return nil
}

func (m *Customer) contextValidateCustomerID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "customerId", "body", int64(m.CustomerID)); err != nil {
		return err
	}

	return nil
}

func (m *Customer) contextValidateUniverseUUIDs(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "universeUUIDs", "body", []strfmt.UUID(m.UniverseUUIDs)); err != nil {
		return err
	}

	return nil
}

func (m *Customer) contextValidateUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "uuid", "body", strfmt.UUID(m.UUID)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Customer) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Customer) UnmarshalBinary(b []byte) error {
	var res Customer
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
