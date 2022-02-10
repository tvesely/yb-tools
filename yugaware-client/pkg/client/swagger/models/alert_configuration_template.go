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

// AlertConfigurationTemplate Alert configuration template
//
// swagger:model AlertConfigurationTemplate
type AlertConfigurationTemplate struct {

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

	// Is alert threshold condition read-only or configurable
	// Read Only: true
	ThresholdConditionReadOnly *bool `json:"thresholdConditionReadOnly,omitempty"`

	// Is alert threshold integer or floating point
	// Read Only: true
	ThresholdInteger *bool `json:"thresholdInteger,omitempty"`

	// Alert threshold maximal value
	// Read Only: true
	ThresholdMaxValue float64 `json:"thresholdMaxValue,omitempty"`

	// Alert threshold minimal value
	// Read Only: true
	ThresholdMinValue float64 `json:"thresholdMinValue,omitempty"`

	// Is alert threshold read-only or configurable
	// Read Only: true
	ThresholdReadOnly *bool `json:"thresholdReadOnly,omitempty"`

	// Threshold unit
	// Required: true
	// Read Only: true
	// Enum: [STATUS COUNT PERCENT MILLISECOND SECOND DAY]
	ThresholdUnit string `json:"thresholdUnit"`

	// Threshold unit name
	// Read Only: true
	ThresholdUnitName string `json:"thresholdUnitName,omitempty"`

	// Thresholds
	// Required: true
	Thresholds map[string]AlertConfigurationThreshold `json:"thresholds"`

	// Configuration UUID
	// Read Only: true
	// Format: uuid
	UUID strfmt.UUID `json:"uuid,omitempty"`
}

// Validate validates this alert configuration template
func (m *AlertConfigurationTemplate) Validate(formats strfmt.Registry) error {
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

func (m *AlertConfigurationTemplate) validateActive(formats strfmt.Registry) error {

	if err := validate.Required("active", "body", m.Active); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateCreateTime(formats strfmt.Registry) error {

	if err := validate.Required("createTime", "body", strfmt.DateTime(m.CreateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("createTime", "body", "date-time", m.CreateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateCustomerUUID(formats strfmt.Registry) error {

	if err := validate.Required("customerUUID", "body", strfmt.UUID(m.CustomerUUID)); err != nil {
		return err
	}

	if err := validate.FormatOf("customerUUID", "body", "uuid", m.CustomerUUID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateDefaultDestination(formats strfmt.Registry) error {

	if err := validate.Required("defaultDestination", "body", m.DefaultDestination); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateDescription(formats strfmt.Registry) error {

	if err := validate.Required("description", "body", m.Description); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateDestinationUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.DestinationUUID) { // not required
		return nil
	}

	if err := validate.FormatOf("destinationUUID", "body", "uuid", m.DestinationUUID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateDurationSec(formats strfmt.Registry) error {

	if err := validate.Required("durationSec", "body", m.DurationSec); err != nil {
		return err
	}

	if err := validate.MinimumInt("durationSec", "body", int64(*m.DurationSec), 0, false); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateName(formats strfmt.Registry) error {

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

func (m *AlertConfigurationTemplate) validateTarget(formats strfmt.Registry) error {

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

var alertConfigurationTemplateTypeTargetTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["PLATFORM","UNIVERSE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alertConfigurationTemplateTypeTargetTypePropEnum = append(alertConfigurationTemplateTypeTargetTypePropEnum, v)
	}
}

const (

	// AlertConfigurationTemplateTargetTypePLATFORM captures enum value "PLATFORM"
	AlertConfigurationTemplateTargetTypePLATFORM string = "PLATFORM"

	// AlertConfigurationTemplateTargetTypeUNIVERSE captures enum value "UNIVERSE"
	AlertConfigurationTemplateTargetTypeUNIVERSE string = "UNIVERSE"
)

// prop value enum
func (m *AlertConfigurationTemplate) validateTargetTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alertConfigurationTemplateTypeTargetTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AlertConfigurationTemplate) validateTargetType(formats strfmt.Registry) error {

	if err := validate.RequiredString("targetType", "body", m.TargetType); err != nil {
		return err
	}

	// value enum
	if err := m.validateTargetTypeEnum("targetType", "body", m.TargetType); err != nil {
		return err
	}

	return nil
}

var alertConfigurationTemplateTypeTemplatePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["REPLICATION_LAG","CLOCK_SKEW","MEMORY_CONSUMPTION","HEALTH_CHECK_ERROR","HEALTH_CHECK_NOTIFICATION_ERROR","BACKUP_FAILURE","BACKUP_SCHEDULE_FAILURE","INACTIVE_CRON_NODES","ALERT_QUERY_FAILED","ALERT_CONFIG_WRITING_FAILED","ALERT_NOTIFICATION_ERROR","ALERT_NOTIFICATION_CHANNEL_ERROR","NODE_DOWN","NODE_RESTART","NODE_CPU_USAGE","NODE_DISK_USAGE","NODE_FILE_DESCRIPTORS_USAGE","DB_VERSION_MISMATCH","DB_INSTANCE_DOWN","DB_INSTANCE_RESTART","DB_FATAL_LOGS","DB_ERROR_LOGS","DB_CORE_FILES","DB_YSQL_CONNECTION","DB_YCQL_CONNECTION","DB_REDIS_CONNECTION","NODE_TO_NODE_CA_CERT_EXPIRY","NODE_TO_NODE_CERT_EXPIRY","CLIENT_TO_NODE_CA_CERT_EXPIRY","CLIENT_TO_NODE_CERT_EXPIRY","YSQL_OP_AVG_LATENCY","YCQL_OP_AVG_LATENCY","YSQL_OP_P99_LATENCY","YCQL_OP_P99_LATENCY","HIGH_NUM_YCQL_CONNECTIONS","HIGH_NUM_YEDIS_CONNECTIONS","YSQL_THROUGHPUT","YCQL_THROUGHPUT"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alertConfigurationTemplateTypeTemplatePropEnum = append(alertConfigurationTemplateTypeTemplatePropEnum, v)
	}
}

const (

	// AlertConfigurationTemplateTemplateREPLICATIONLAG captures enum value "REPLICATION_LAG"
	AlertConfigurationTemplateTemplateREPLICATIONLAG string = "REPLICATION_LAG"

	// AlertConfigurationTemplateTemplateCLOCKSKEW captures enum value "CLOCK_SKEW"
	AlertConfigurationTemplateTemplateCLOCKSKEW string = "CLOCK_SKEW"

	// AlertConfigurationTemplateTemplateMEMORYCONSUMPTION captures enum value "MEMORY_CONSUMPTION"
	AlertConfigurationTemplateTemplateMEMORYCONSUMPTION string = "MEMORY_CONSUMPTION"

	// AlertConfigurationTemplateTemplateHEALTHCHECKERROR captures enum value "HEALTH_CHECK_ERROR"
	AlertConfigurationTemplateTemplateHEALTHCHECKERROR string = "HEALTH_CHECK_ERROR"

	// AlertConfigurationTemplateTemplateHEALTHCHECKNOTIFICATIONERROR captures enum value "HEALTH_CHECK_NOTIFICATION_ERROR"
	AlertConfigurationTemplateTemplateHEALTHCHECKNOTIFICATIONERROR string = "HEALTH_CHECK_NOTIFICATION_ERROR"

	// AlertConfigurationTemplateTemplateBACKUPFAILURE captures enum value "BACKUP_FAILURE"
	AlertConfigurationTemplateTemplateBACKUPFAILURE string = "BACKUP_FAILURE"

	// AlertConfigurationTemplateTemplateBACKUPSCHEDULEFAILURE captures enum value "BACKUP_SCHEDULE_FAILURE"
	AlertConfigurationTemplateTemplateBACKUPSCHEDULEFAILURE string = "BACKUP_SCHEDULE_FAILURE"

	// AlertConfigurationTemplateTemplateINACTIVECRONNODES captures enum value "INACTIVE_CRON_NODES"
	AlertConfigurationTemplateTemplateINACTIVECRONNODES string = "INACTIVE_CRON_NODES"

	// AlertConfigurationTemplateTemplateALERTQUERYFAILED captures enum value "ALERT_QUERY_FAILED"
	AlertConfigurationTemplateTemplateALERTQUERYFAILED string = "ALERT_QUERY_FAILED"

	// AlertConfigurationTemplateTemplateALERTCONFIGWRITINGFAILED captures enum value "ALERT_CONFIG_WRITING_FAILED"
	AlertConfigurationTemplateTemplateALERTCONFIGWRITINGFAILED string = "ALERT_CONFIG_WRITING_FAILED"

	// AlertConfigurationTemplateTemplateALERTNOTIFICATIONERROR captures enum value "ALERT_NOTIFICATION_ERROR"
	AlertConfigurationTemplateTemplateALERTNOTIFICATIONERROR string = "ALERT_NOTIFICATION_ERROR"

	// AlertConfigurationTemplateTemplateALERTNOTIFICATIONCHANNELERROR captures enum value "ALERT_NOTIFICATION_CHANNEL_ERROR"
	AlertConfigurationTemplateTemplateALERTNOTIFICATIONCHANNELERROR string = "ALERT_NOTIFICATION_CHANNEL_ERROR"

	// AlertConfigurationTemplateTemplateNODEDOWN captures enum value "NODE_DOWN"
	AlertConfigurationTemplateTemplateNODEDOWN string = "NODE_DOWN"

	// AlertConfigurationTemplateTemplateNODERESTART captures enum value "NODE_RESTART"
	AlertConfigurationTemplateTemplateNODERESTART string = "NODE_RESTART"

	// AlertConfigurationTemplateTemplateNODECPUUSAGE captures enum value "NODE_CPU_USAGE"
	AlertConfigurationTemplateTemplateNODECPUUSAGE string = "NODE_CPU_USAGE"

	// AlertConfigurationTemplateTemplateNODEDISKUSAGE captures enum value "NODE_DISK_USAGE"
	AlertConfigurationTemplateTemplateNODEDISKUSAGE string = "NODE_DISK_USAGE"

	// AlertConfigurationTemplateTemplateNODEFILEDESCRIPTORSUSAGE captures enum value "NODE_FILE_DESCRIPTORS_USAGE"
	AlertConfigurationTemplateTemplateNODEFILEDESCRIPTORSUSAGE string = "NODE_FILE_DESCRIPTORS_USAGE"

	// AlertConfigurationTemplateTemplateDBVERSIONMISMATCH captures enum value "DB_VERSION_MISMATCH"
	AlertConfigurationTemplateTemplateDBVERSIONMISMATCH string = "DB_VERSION_MISMATCH"

	// AlertConfigurationTemplateTemplateDBINSTANCEDOWN captures enum value "DB_INSTANCE_DOWN"
	AlertConfigurationTemplateTemplateDBINSTANCEDOWN string = "DB_INSTANCE_DOWN"

	// AlertConfigurationTemplateTemplateDBINSTANCERESTART captures enum value "DB_INSTANCE_RESTART"
	AlertConfigurationTemplateTemplateDBINSTANCERESTART string = "DB_INSTANCE_RESTART"

	// AlertConfigurationTemplateTemplateDBFATALLOGS captures enum value "DB_FATAL_LOGS"
	AlertConfigurationTemplateTemplateDBFATALLOGS string = "DB_FATAL_LOGS"

	// AlertConfigurationTemplateTemplateDBERRORLOGS captures enum value "DB_ERROR_LOGS"
	AlertConfigurationTemplateTemplateDBERRORLOGS string = "DB_ERROR_LOGS"

	// AlertConfigurationTemplateTemplateDBCOREFILES captures enum value "DB_CORE_FILES"
	AlertConfigurationTemplateTemplateDBCOREFILES string = "DB_CORE_FILES"

	// AlertConfigurationTemplateTemplateDBYSQLCONNECTION captures enum value "DB_YSQL_CONNECTION"
	AlertConfigurationTemplateTemplateDBYSQLCONNECTION string = "DB_YSQL_CONNECTION"

	// AlertConfigurationTemplateTemplateDBYCQLCONNECTION captures enum value "DB_YCQL_CONNECTION"
	AlertConfigurationTemplateTemplateDBYCQLCONNECTION string = "DB_YCQL_CONNECTION"

	// AlertConfigurationTemplateTemplateDBREDISCONNECTION captures enum value "DB_REDIS_CONNECTION"
	AlertConfigurationTemplateTemplateDBREDISCONNECTION string = "DB_REDIS_CONNECTION"

	// AlertConfigurationTemplateTemplateNODETONODECACERTEXPIRY captures enum value "NODE_TO_NODE_CA_CERT_EXPIRY"
	AlertConfigurationTemplateTemplateNODETONODECACERTEXPIRY string = "NODE_TO_NODE_CA_CERT_EXPIRY"

	// AlertConfigurationTemplateTemplateNODETONODECERTEXPIRY captures enum value "NODE_TO_NODE_CERT_EXPIRY"
	AlertConfigurationTemplateTemplateNODETONODECERTEXPIRY string = "NODE_TO_NODE_CERT_EXPIRY"

	// AlertConfigurationTemplateTemplateCLIENTTONODECACERTEXPIRY captures enum value "CLIENT_TO_NODE_CA_CERT_EXPIRY"
	AlertConfigurationTemplateTemplateCLIENTTONODECACERTEXPIRY string = "CLIENT_TO_NODE_CA_CERT_EXPIRY"

	// AlertConfigurationTemplateTemplateCLIENTTONODECERTEXPIRY captures enum value "CLIENT_TO_NODE_CERT_EXPIRY"
	AlertConfigurationTemplateTemplateCLIENTTONODECERTEXPIRY string = "CLIENT_TO_NODE_CERT_EXPIRY"

	// AlertConfigurationTemplateTemplateYSQLOPAVGLATENCY captures enum value "YSQL_OP_AVG_LATENCY"
	AlertConfigurationTemplateTemplateYSQLOPAVGLATENCY string = "YSQL_OP_AVG_LATENCY"

	// AlertConfigurationTemplateTemplateYCQLOPAVGLATENCY captures enum value "YCQL_OP_AVG_LATENCY"
	AlertConfigurationTemplateTemplateYCQLOPAVGLATENCY string = "YCQL_OP_AVG_LATENCY"

	// AlertConfigurationTemplateTemplateYSQLOPP99LATENCY captures enum value "YSQL_OP_P99_LATENCY"
	AlertConfigurationTemplateTemplateYSQLOPP99LATENCY string = "YSQL_OP_P99_LATENCY"

	// AlertConfigurationTemplateTemplateYCQLOPP99LATENCY captures enum value "YCQL_OP_P99_LATENCY"
	AlertConfigurationTemplateTemplateYCQLOPP99LATENCY string = "YCQL_OP_P99_LATENCY"

	// AlertConfigurationTemplateTemplateHIGHNUMYCQLCONNECTIONS captures enum value "HIGH_NUM_YCQL_CONNECTIONS"
	AlertConfigurationTemplateTemplateHIGHNUMYCQLCONNECTIONS string = "HIGH_NUM_YCQL_CONNECTIONS"

	// AlertConfigurationTemplateTemplateHIGHNUMYEDISCONNECTIONS captures enum value "HIGH_NUM_YEDIS_CONNECTIONS"
	AlertConfigurationTemplateTemplateHIGHNUMYEDISCONNECTIONS string = "HIGH_NUM_YEDIS_CONNECTIONS"

	// AlertConfigurationTemplateTemplateYSQLTHROUGHPUT captures enum value "YSQL_THROUGHPUT"
	AlertConfigurationTemplateTemplateYSQLTHROUGHPUT string = "YSQL_THROUGHPUT"

	// AlertConfigurationTemplateTemplateYCQLTHROUGHPUT captures enum value "YCQL_THROUGHPUT"
	AlertConfigurationTemplateTemplateYCQLTHROUGHPUT string = "YCQL_THROUGHPUT"
)

// prop value enum
func (m *AlertConfigurationTemplate) validateTemplateEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alertConfigurationTemplateTypeTemplatePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AlertConfigurationTemplate) validateTemplate(formats strfmt.Registry) error {

	if err := validate.RequiredString("template", "body", m.Template); err != nil {
		return err
	}

	// value enum
	if err := m.validateTemplateEnum("template", "body", m.Template); err != nil {
		return err
	}

	return nil
}

var alertConfigurationTemplateTypeThresholdUnitPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["STATUS","COUNT","PERCENT","MILLISECOND","SECOND","DAY"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alertConfigurationTemplateTypeThresholdUnitPropEnum = append(alertConfigurationTemplateTypeThresholdUnitPropEnum, v)
	}
}

const (

	// AlertConfigurationTemplateThresholdUnitSTATUS captures enum value "STATUS"
	AlertConfigurationTemplateThresholdUnitSTATUS string = "STATUS"

	// AlertConfigurationTemplateThresholdUnitCOUNT captures enum value "COUNT"
	AlertConfigurationTemplateThresholdUnitCOUNT string = "COUNT"

	// AlertConfigurationTemplateThresholdUnitPERCENT captures enum value "PERCENT"
	AlertConfigurationTemplateThresholdUnitPERCENT string = "PERCENT"

	// AlertConfigurationTemplateThresholdUnitMILLISECOND captures enum value "MILLISECOND"
	AlertConfigurationTemplateThresholdUnitMILLISECOND string = "MILLISECOND"

	// AlertConfigurationTemplateThresholdUnitSECOND captures enum value "SECOND"
	AlertConfigurationTemplateThresholdUnitSECOND string = "SECOND"

	// AlertConfigurationTemplateThresholdUnitDAY captures enum value "DAY"
	AlertConfigurationTemplateThresholdUnitDAY string = "DAY"
)

// prop value enum
func (m *AlertConfigurationTemplate) validateThresholdUnitEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alertConfigurationTemplateTypeThresholdUnitPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AlertConfigurationTemplate) validateThresholdUnit(formats strfmt.Registry) error {

	if err := validate.RequiredString("thresholdUnit", "body", m.ThresholdUnit); err != nil {
		return err
	}

	// value enum
	if err := m.validateThresholdUnitEnum("thresholdUnit", "body", m.ThresholdUnit); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) validateThresholds(formats strfmt.Registry) error {

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

func (m *AlertConfigurationTemplate) validateUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.UUID) { // not required
		return nil
	}

	if err := validate.FormatOf("uuid", "body", "uuid", m.UUID.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this alert configuration template based on the context it is used
func (m *AlertConfigurationTemplate) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

	if err := m.contextValidateThresholdConditionReadOnly(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholdInteger(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholdMaxValue(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholdMinValue(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholdReadOnly(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholdUnit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThresholdUnitName(ctx, formats); err != nil {
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

func (m *AlertConfigurationTemplate) contextValidateCreateTime(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "createTime", "body", strfmt.DateTime(m.CreateTime)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateCustomerUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "customerUUID", "body", strfmt.UUID(m.CustomerUUID)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateTarget(ctx context.Context, formats strfmt.Registry) error {

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

func (m *AlertConfigurationTemplate) contextValidateTargetType(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "targetType", "body", string(m.TargetType)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateTemplate(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "template", "body", string(m.Template)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholdConditionReadOnly(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdConditionReadOnly", "body", m.ThresholdConditionReadOnly); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholdInteger(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdInteger", "body", m.ThresholdInteger); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholdMaxValue(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdMaxValue", "body", float64(m.ThresholdMaxValue)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholdMinValue(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdMinValue", "body", float64(m.ThresholdMinValue)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholdReadOnly(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdReadOnly", "body", m.ThresholdReadOnly); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholdUnit(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdUnit", "body", string(m.ThresholdUnit)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholdUnitName(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "thresholdUnitName", "body", string(m.ThresholdUnitName)); err != nil {
		return err
	}

	return nil
}

func (m *AlertConfigurationTemplate) contextValidateThresholds(ctx context.Context, formats strfmt.Registry) error {

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

func (m *AlertConfigurationTemplate) contextValidateUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "uuid", "body", strfmt.UUID(m.UUID)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AlertConfigurationTemplate) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AlertConfigurationTemplate) UnmarshalBinary(b []byte) error {
	var res AlertConfigurationTemplate
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
