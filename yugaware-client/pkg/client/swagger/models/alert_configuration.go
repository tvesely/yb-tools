// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AlertConfiguration Alert configuration
//
// swagger:model AlertConfiguration
type AlertConfiguration struct {

	// Is configured alerts raised or not
	// Required: true
	Active *bool `json:"active"`

	// Creation time
	// Required: true
	// Read Only: true
	// Format: date-time
	CreateTime strfmt.DateTime `json:"createTime"`

	// Customer UUID
	// Required: true
	// Read Only: true
	// Format: uuid
	CustomerUUID strfmt.UUID `json:"customerUUID"`

	// Is default destination used for this config
	// Required: true
	DefaultDestination *bool `json:"defaultDestination"`

	// Description
	// Required: true
	Description *string `json:"description"`

	// Alert destination UUID
	// Format: uuid
	DestinationUUID strfmt.UUID `json:"destinationUUID,omitempty"`

	// Duration in seconds, while condition is met to raise an alert
	// Required: true
	// Minimum: 0
	DurationSec *int32 `json:"durationSec"`

	// Name
	// Required: true
	// Max Length: 1000
	// Min Length: 1
	Name *string `json:"name"`

	// Target
	// Required: true
	Target *AlertConfigurationTarget `json:"target"`

	// Target type
	// Required: true
	// Read Only: true
	// Enum: [PLATFORM UNIVERSE]
	TargetType string `json:"targetType"`

	// Template name
	// Required: true
	// Read Only: true
	// Enum: [REPLICATION_LAG CLOCK_SKEW MEMORY_CONSUMPTION HEALTH_CHECK_ERROR HEALTH_CHECK_NOTIFICATION_ERROR BACKUP_FAILURE BACKUP_SCHEDULE_FAILURE INACTIVE_CRON_NODES ALERT_QUERY_FAILED ALERT_CONFIG_WRITING_FAILED ALERT_NOTIFICATION_ERROR ALERT_NOTIFICATION_CHANNEL_ERROR NODE_DOWN NODE_RESTART NODE_CPU_USAGE NODE_DISK_USAGE NODE_FILE_DESCRIPTORS_USAGE DB_VERSION_MISMATCH DB_INSTANCE_DOWN DB_INSTANCE_RESTART DB_FATAL_LOGS DB_ERROR_LOGS DB_CORE_FILES DB_YSQL_CONNECTION DB_YCQL_CONNECTION DB_REDIS_CONNECTION NODE_TO_NODE_CA_CERT_EXPIRY NODE_TO_NODE_CERT_EXPIRY CLIENT_TO_NODE_CA_CERT_EXPIRY CLIENT_TO_NODE_CERT_EXPIRY YSQL_OP_AVG_LATENCY YCQL_OP_AVG_LATENCY YSQL_OP_P99_LATENCY YCQL_OP_P99_LATENCY HIGH_NUM_YCQL_CONNECTIONS HIGH_NUM_YEDIS_CONNECTIONS YSQL_THROUGHPUT YCQL_THROUGHPUT]
	Template string `json:"template"`

	// Threshold unit
	// Required: true
	// Read Only: true
	// Enum: [STATUS COUNT PERCENT MILLISECOND SECOND DAY]
	ThresholdUnit string `json:"thresholdUnit"`

	// Thresholds
	// Required: true
	Thresholds map[string]AlertConfigurationThreshold `json:"thresholds"`

	// Configuration UUID
	// Read Only: true
	// Format: uuid
	UUID strfmt.UUID `json:"uuid,omitempty"`
}

// Validate validates this alert configuration
func (m *AlertConfiguration) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActive(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerUUID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultDestination(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDestinationUUID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDurationSec(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTarget(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTemplate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateThresholdUnit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateThresholds(formats); err != nil {
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

func (m *AlertConfiguration) validateActive(formats strfmt.Registry) error {

	if err := validate.Required("active", "body", m.Active); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateCreateTime(formats strfmt.Registry) error {

	if err := validate.Required("createTime", "body", strfmt.DateTime(m.CreateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("createTime", "body", "date-time", m.CreateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateCustomerUUID(formats strfmt.Registry) error {

	if err := validate.Required("customerUUID", "body", strfmt.UUID(m.CustomerUUID)); err != nil {
		return err
	}

	if err := validate.FormatOf("customerUUID", "body", "uuid", m.CustomerUUID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateDefaultDestination(formats strfmt.Registry) error {

	if err := validate.Required("defaultDestination", "body", m.DefaultDestination); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateDescription(formats strfmt.Registry) error {

	if err := validate.Required("description", "body", m.Description); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateDestinationUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.DestinationUUID) { // not required
		return nil
	}

	if err := validate.FormatOf("destinationUUID", "body", "uuid", m.DestinationUUID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateDurationSec(formats strfmt.Registry) error {

	if err := validate.Required("durationSec", "body", m.DurationSec); err != nil {
		return err
	}

	if err := validate.MinimumInt("durationSec", "body", int64(*m.DurationSec), 0, false); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	if err := validate.MinLength("name", "body", *m.Name, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("name", "body", *m.Name, 1000); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateTarget(formats strfmt.Registry) error {

	if err := validate.Required("target", "body", m.Target); err != nil {
		return err
	}

	if m.Target != nil {
		if err := m.Target.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("target")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("target")
			}
			return err
		}
	}

	return nil
}

var alertConfigurationTypeTargetTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["PLATFORM","UNIVERSE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alertConfigurationTypeTargetTypePropEnum = append(alertConfigurationTypeTargetTypePropEnum, v)
	}
}

const (

	// AlertConfigurationTargetTypePLATFORM captures enum value "PLATFORM"
	AlertConfigurationTargetTypePLATFORM string = "PLATFORM"

	// AlertConfigurationTargetTypeUNIVERSE captures enum value "UNIVERSE"
	AlertConfigurationTargetTypeUNIVERSE string = "UNIVERSE"
)

// prop value enum
func (m *AlertConfiguration) validateTargetTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alertConfigurationTypeTargetTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AlertConfiguration) validateTargetType(formats strfmt.Registry) error {

	if err := validate.RequiredString("targetType", "body", m.TargetType); err != nil {
		return err
	}

	// value enum
	if err := m.validateTargetTypeEnum("targetType", "body", m.TargetType); err != nil {
		return err
	}

	return nil
}

var alertConfigurationTypeTemplatePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["REPLICATION_LAG","CLOCK_SKEW","MEMORY_CONSUMPTION","HEALTH_CHECK_ERROR","HEALTH_CHECK_NOTIFICATION_ERROR","BACKUP_FAILURE","BACKUP_SCHEDULE_FAILURE","INACTIVE_CRON_NODES","ALERT_QUERY_FAILED","ALERT_CONFIG_WRITING_FAILED","ALERT_NOTIFICATION_ERROR","ALERT_NOTIFICATION_CHANNEL_ERROR","NODE_DOWN","NODE_RESTART","NODE_CPU_USAGE","NODE_DISK_USAGE","NODE_FILE_DESCRIPTORS_USAGE","DB_VERSION_MISMATCH","DB_INSTANCE_DOWN","DB_INSTANCE_RESTART","DB_FATAL_LOGS","DB_ERROR_LOGS","DB_CORE_FILES","DB_YSQL_CONNECTION","DB_YCQL_CONNECTION","DB_REDIS_CONNECTION","NODE_TO_NODE_CA_CERT_EXPIRY","NODE_TO_NODE_CERT_EXPIRY","CLIENT_TO_NODE_CA_CERT_EXPIRY","CLIENT_TO_NODE_CERT_EXPIRY","YSQL_OP_AVG_LATENCY","YCQL_OP_AVG_LATENCY","YSQL_OP_P99_LATENCY","YCQL_OP_P99_LATENCY","HIGH_NUM_YCQL_CONNECTIONS","HIGH_NUM_YEDIS_CONNECTIONS","YSQL_THROUGHPUT","YCQL_THROUGHPUT"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alertConfigurationTypeTemplatePropEnum = append(alertConfigurationTypeTemplatePropEnum, v)
	}
}

const (

	// AlertConfigurationTemplateREPLICATIONLAG captures enum value "REPLICATION_LAG"
	AlertConfigurationTemplateREPLICATIONLAG string = "REPLICATION_LAG"

	// AlertConfigurationTemplateCLOCKSKEW captures enum value "CLOCK_SKEW"
	AlertConfigurationTemplateCLOCKSKEW string = "CLOCK_SKEW"

	// AlertConfigurationTemplateMEMORYCONSUMPTION captures enum value "MEMORY_CONSUMPTION"
	AlertConfigurationTemplateMEMORYCONSUMPTION string = "MEMORY_CONSUMPTION"

	// AlertConfigurationTemplateHEALTHCHECKERROR captures enum value "HEALTH_CHECK_ERROR"
	AlertConfigurationTemplateHEALTHCHECKERROR string = "HEALTH_CHECK_ERROR"

	// AlertConfigurationTemplateHEALTHCHECKNOTIFICATIONERROR captures enum value "HEALTH_CHECK_NOTIFICATION_ERROR"
	AlertConfigurationTemplateHEALTHCHECKNOTIFICATIONERROR string = "HEALTH_CHECK_NOTIFICATION_ERROR"

	// AlertConfigurationTemplateBACKUPFAILURE captures enum value "BACKUP_FAILURE"
	AlertConfigurationTemplateBACKUPFAILURE string = "BACKUP_FAILURE"

	// AlertConfigurationTemplateBACKUPSCHEDULEFAILURE captures enum value "BACKUP_SCHEDULE_FAILURE"
	AlertConfigurationTemplateBACKUPSCHEDULEFAILURE string = "BACKUP_SCHEDULE_FAILURE"

	// AlertConfigurationTemplateINACTIVECRONNODES captures enum value "INACTIVE_CRON_NODES"
	AlertConfigurationTemplateINACTIVECRONNODES string = "INACTIVE_CRON_NODES"

	// AlertConfigurationTemplateALERTQUERYFAILED captures enum value "ALERT_QUERY_FAILED"
	AlertConfigurationTemplateALERTQUERYFAILED string = "ALERT_QUERY_FAILED"

	// AlertConfigurationTemplateALERTCONFIGWRITINGFAILED captures enum value "ALERT_CONFIG_WRITING_FAILED"
	AlertConfigurationTemplateALERTCONFIGWRITINGFAILED string = "ALERT_CONFIG_WRITING_FAILED"

	// AlertConfigurationTemplateALERTNOTIFICATIONERROR captures enum value "ALERT_NOTIFICATION_ERROR"
	AlertConfigurationTemplateALERTNOTIFICATIONERROR string = "ALERT_NOTIFICATION_ERROR"

	// AlertConfigurationTemplateALERTNOTIFICATIONCHANNELERROR captures enum value "ALERT_NOTIFICATION_CHANNEL_ERROR"
	AlertConfigurationTemplateALERTNOTIFICATIONCHANNELERROR string = "ALERT_NOTIFICATION_CHANNEL_ERROR"

	// AlertConfigurationTemplateNODEDOWN captures enum value "NODE_DOWN"
	AlertConfigurationTemplateNODEDOWN string = "NODE_DOWN"

	// AlertConfigurationTemplateNODERESTART captures enum value "NODE_RESTART"
	AlertConfigurationTemplateNODERESTART string = "NODE_RESTART"

	// AlertConfigurationTemplateNODECPUUSAGE captures enum value "NODE_CPU_USAGE"
	AlertConfigurationTemplateNODECPUUSAGE string = "NODE_CPU_USAGE"

	// AlertConfigurationTemplateNODEDISKUSAGE captures enum value "NODE_DISK_USAGE"
	AlertConfigurationTemplateNODEDISKUSAGE string = "NODE_DISK_USAGE"

	// AlertConfigurationTemplateNODEFILEDESCRIPTORSUSAGE captures enum value "NODE_FILE_DESCRIPTORS_USAGE"
	AlertConfigurationTemplateNODEFILEDESCRIPTORSUSAGE string = "NODE_FILE_DESCRIPTORS_USAGE"

	// AlertConfigurationTemplateDBVERSIONMISMATCH captures enum value "DB_VERSION_MISMATCH"
	AlertConfigurationTemplateDBVERSIONMISMATCH string = "DB_VERSION_MISMATCH"

	// AlertConfigurationTemplateDBINSTANCEDOWN captures enum value "DB_INSTANCE_DOWN"
	AlertConfigurationTemplateDBINSTANCEDOWN string = "DB_INSTANCE_DOWN"

	// AlertConfigurationTemplateDBINSTANCERESTART captures enum value "DB_INSTANCE_RESTART"
	AlertConfigurationTemplateDBINSTANCERESTART string = "DB_INSTANCE_RESTART"

	// AlertConfigurationTemplateDBFATALLOGS captures enum value "DB_FATAL_LOGS"
	AlertConfigurationTemplateDBFATALLOGS string = "DB_FATAL_LOGS"

	// AlertConfigurationTemplateDBERRORLOGS captures enum value "DB_ERROR_LOGS"
	AlertConfigurationTemplateDBERRORLOGS string = "DB_ERROR_LOGS"

	// AlertConfigurationTemplateDBCOREFILES captures enum value "DB_CORE_FILES"
	AlertConfigurationTemplateDBCOREFILES string = "DB_CORE_FILES"

	// AlertConfigurationTemplateDBYSQLCONNECTION captures enum value "DB_YSQL_CONNECTION"
	AlertConfigurationTemplateDBYSQLCONNECTION string = "DB_YSQL_CONNECTION"

	// AlertConfigurationTemplateDBYCQLCONNECTION captures enum value "DB_YCQL_CONNECTION"
	AlertConfigurationTemplateDBYCQLCONNECTION string = "DB_YCQL_CONNECTION"

	// AlertConfigurationTemplateDBREDISCONNECTION captures enum value "DB_REDIS_CONNECTION"
	AlertConfigurationTemplateDBREDISCONNECTION string = "DB_REDIS_CONNECTION"

	// AlertConfigurationTemplateNODETONODECACERTEXPIRY captures enum value "NODE_TO_NODE_CA_CERT_EXPIRY"
	AlertConfigurationTemplateNODETONODECACERTEXPIRY string = "NODE_TO_NODE_CA_CERT_EXPIRY"

	// AlertConfigurationTemplateNODETONODECERTEXPIRY captures enum value "NODE_TO_NODE_CERT_EXPIRY"
	AlertConfigurationTemplateNODETONODECERTEXPIRY string = "NODE_TO_NODE_CERT_EXPIRY"

	// AlertConfigurationTemplateCLIENTTONODECACERTEXPIRY captures enum value "CLIENT_TO_NODE_CA_CERT_EXPIRY"
	AlertConfigurationTemplateCLIENTTONODECACERTEXPIRY string = "CLIENT_TO_NODE_CA_CERT_EXPIRY"

	// AlertConfigurationTemplateCLIENTTONODECERTEXPIRY captures enum value "CLIENT_TO_NODE_CERT_EXPIRY"
	AlertConfigurationTemplateCLIENTTONODECERTEXPIRY string = "CLIENT_TO_NODE_CERT_EXPIRY"

	// AlertConfigurationTemplateYSQLOPAVGLATENCY captures enum value "YSQL_OP_AVG_LATENCY"
	AlertConfigurationTemplateYSQLOPAVGLATENCY string = "YSQL_OP_AVG_LATENCY"

	// AlertConfigurationTemplateYCQLOPAVGLATENCY captures enum value "YCQL_OP_AVG_LATENCY"
	AlertConfigurationTemplateYCQLOPAVGLATENCY string = "YCQL_OP_AVG_LATENCY"

	// AlertConfigurationTemplateYSQLOPP99LATENCY captures enum value "YSQL_OP_P99_LATENCY"
	AlertConfigurationTemplateYSQLOPP99LATENCY string = "YSQL_OP_P99_LATENCY"

	// AlertConfigurationTemplateYCQLOPP99LATENCY captures enum value "YCQL_OP_P99_LATENCY"
	AlertConfigurationTemplateYCQLOPP99LATENCY string = "YCQL_OP_P99_LATENCY"

	// AlertConfigurationTemplateHIGHNUMYCQLCONNECTIONS captures enum value "HIGH_NUM_YCQL_CONNECTIONS"
	AlertConfigurationTemplateHIGHNUMYCQLCONNECTIONS string = "HIGH_NUM_YCQL_CONNECTIONS"

	// AlertConfigurationTemplateHIGHNUMYEDISCONNECTIONS captures enum value "HIGH_NUM_YEDIS_CONNECTIONS"
	AlertConfigurationTemplateHIGHNUMYEDISCONNECTIONS string = "HIGH_NUM_YEDIS_CONNECTIONS"

	// AlertConfigurationTemplateYSQLTHROUGHPUT captures enum value "YSQL_THROUGHPUT"
	AlertConfigurationTemplateYSQLTHROUGHPUT string = "YSQL_THROUGHPUT"

	// AlertConfigurationTemplateYCQLTHROUGHPUT captures enum value "YCQL_THROUGHPUT"
	AlertConfigurationTemplateYCQLTHROUGHPUT string = "YCQL_THROUGHPUT"
)

// prop value enum
func (m *AlertConfiguration) validateTemplateEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alertConfigurationTypeTemplatePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AlertConfiguration) validateTemplate(formats strfmt.Registry) error {

	if err := validate.RequiredString("template", "body", m.Template); err != nil {
		return err
	}

	// value enum
	if err := m.validateTemplateEnum("template", "body", m.Template); err != nil {
		return err
	}

	return nil
}

var alertConfigurationTypeThresholdUnitPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["STATUS","COUNT","PERCENT","MILLISECOND","SECOND","DAY"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alertConfigurationTypeThresholdUnitPropEnum = append(alertConfigurationTypeThresholdUnitPropEnum, v)
	}
}

const (

	// AlertConfigurationThresholdUnitSTATUS captures enum value "STATUS"
	AlertConfigurationThresholdUnitSTATUS string = "STATUS"

	// AlertConfigurationThresholdUnitCOUNT captures enum value "COUNT"
	AlertConfigurationThresholdUnitCOUNT string = "COUNT"

	// AlertConfigurationThresholdUnitPERCENT captures enum value "PERCENT"
	AlertConfigurationThresholdUnitPERCENT string = "PERCENT"

	// AlertConfigurationThresholdUnitMILLISECOND captures enum value "MILLISECOND"
	AlertConfigurationThresholdUnitMILLISECOND string = "MILLISECOND"

	// AlertConfigurationThresholdUnitSECOND captures enum value "SECOND"
	AlertConfigurationThresholdUnitSECOND string = "SECOND"

	// AlertConfigurationThresholdUnitDAY captures enum value "DAY"
	AlertConfigurationThresholdUnitDAY string = "DAY"
)

// prop value enum
func (m *AlertConfiguration) validateThresholdUnitEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alertConfigurationTypeThresholdUnitPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AlertConfiguration) validateThresholdUnit(formats strfmt.Registry) error {

	if err := validate.RequiredString("thresholdUnit", "body", m.ThresholdUnit); err != nil {
		return err
	}

	// value enum
	if err := m.validateThresholdUnitEnum("thresholdUnit", "body", m.ThresholdUnit); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) validateThresholds(formats strfmt.Registry) error {

	if err := validate.Required("thresholds", "body", m.Thresholds); err != nil {
		return err
	}

	for k := range m.Thresholds {

		if err := validate.Required("thresholds"+"."+k, "body", m.Thresholds[k]); err != nil {
			return err
		}
		if val, ok := m.Thresholds[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("thresholds" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("thresholds" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *AlertConfiguration) validateUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.UUID) { // not required
		return nil
	}

	if err := validate.FormatOf("uuid", "body", "uuid", m.UUID.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this alert configuration based on the context it is used
func (m *AlertConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreateTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerUUID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTarget(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTargetType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTemplate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholdUnit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholds(ctx, formats); err != nil {
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

func (m *AlertConfiguration) contextValidateCreateTime(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "createTime", "body", strfmt.DateTime(m.CreateTime)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) contextValidateCustomerUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "customerUUID", "body", strfmt.UUID(m.CustomerUUID)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) contextValidateTarget(ctx context.Context, formats strfmt.Registry) error {

	if m.Target != nil {
		if err := m.Target.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("target")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("target")
			}
			return err
		}
	}

	return nil
}

func (m *AlertConfiguration) contextValidateTargetType(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "targetType", "body", string(m.TargetType)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) contextValidateTemplate(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "template", "body", string(m.Template)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) contextValidateThresholdUnit(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdUnit", "body", string(m.ThresholdUnit)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfiguration) contextValidateThresholds(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.Required("thresholds", "body", m.Thresholds); err != nil {
		return err
	}

	for k := range m.Thresholds {

		if val, ok := m.Thresholds[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *AlertConfiguration) contextValidateUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "uuid", "body", strfmt.UUID(m.UUID)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AlertConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AlertConfiguration) UnmarshalBinary(b []byte) error {
	var res AlertConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
