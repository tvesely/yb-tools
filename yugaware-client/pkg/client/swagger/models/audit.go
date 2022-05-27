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

// Audit Audit logging for requests and responses
//
// swagger:model Audit
type Audit struct {

	// Action
	// Example: Create User
	// Read Only: true
	// Enum: [Set Create Edit Update Delete Register Refresh Upload Upgrade Import Pause Resume Restart Abort Retry Restore Alter Drop Stop Validate Acknowledge SyncXClusterConfig Login Promote Bootstrap Configure RefreshPricing UpgradeSoftware UpgradeGFlags UpgradeCerts UpgradeTLS UpgradeVmImage UpgradeSystemd ResizeNode AddMetrics CreateKubernetes SetupDocker RetrieveKmsKey RemoveKmsKeyReferenceHistory UpsertCustomerFeatures CreateSelfSignedCert UpdateEmptyCustomerCertificate GetRootCertificate AddClientCertificate SetDBCredentials CreateUserInDB SetHelm3Compatible SetBackupFlag SetUniverseKey ResetUniverseVersion ConfigUniverseAlert ToggleTls TlsConfigUpdate UpdateDiskSize CreateCluster DeleteCluster CreateAllClusters UpdatePrimaryCluster UpdateReadOnlyCluster CreateReadOnlyCluster DeleteReadOnlyCluster RunYsqlQuery BulkImport CreateBackup RestoreBackup CreateSingleTableBackup CreateMultiTableBackup CreateBackupSchedule EditBackupSchedule StartPeriodicBackup StopPeriodicBackup DetachedNodeInstanceAction NodeInstanceAction DeleteBackupSchedule ChangeUserRole ChangeUserPassword SetSecurity GenerateApiToken ResetSlowQueries ExternalScriptSchedule StopScheduledScript UpdateScheduledScript CreateInstanceType DeleteInstanceType GetUniverseResources]
	Action string `json:"action,omitempty"`

	// API call
	// Example: /api/v1/customers/\u003c496fdea8-df25-11eb-ba80-0242ac130004\u003e/providers
	// Read Only: true
	APICall string `json:"apiCall,omitempty"`

	// API method
	// Example: GET
	// Read Only: true
	APIMethod string `json:"apiMethod,omitempty"`

	// audit ID
	// Required: true
	AuditID *int64 `json:"auditID"`

	// Customer UUID
	// Read Only: true
	// Format: uuid
	CustomerUUID strfmt.UUID `json:"customerUUID,omitempty"`

	// Audit UUID
	// Read Only: true
	Payload interface{} `json:"payload,omitempty"`

	// Target
	// Example: User
	// Read Only: true
	// Enum: [Session CloudProvider Region AvailabilityZone CustomerConfig KMSConfig Customer Release Certificate Alert AlertChannel AlertDestination MaintenanceWindow AccessKey Universe XClusterConfig Table Backup CustomerTask NodeInstance PlatformInstance Schedule User LoggingConfig RuntimeConfigKey HAConfig HABackup ScheduledScript SupportBundle GFlags]
	Target string `json:"target,omitempty"`

	// Target ID
	// Read Only: true
	TargetID string `json:"targetID,omitempty"`

	// Task UUID
	// Read Only: true
	// Format: uuid
	TaskUUID strfmt.UUID `json:"taskUUID,omitempty"`

	// timestamp
	// Required: true
	// Format: date-time
	Timestamp *strfmt.DateTime `json:"timestamp"`

	// User Email
	// Read Only: true
	UserEmail string `json:"userEmail,omitempty"`

	// User UUID
	// Read Only: true
	// Format: uuid
	UserUUID strfmt.UUID `json:"userUUID,omitempty"`
}

// Validate validates this audit
func (m *Audit) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAction(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuditID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerUUID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTarget(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTaskUUID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserUUID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var auditTypeActionPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Set","Create","Edit","Update","Delete","Register","Refresh","Upload","Upgrade","Import","Pause","Resume","Restart","Abort","Retry","Restore","Alter","Drop","Stop","Validate","Acknowledge","SyncXClusterConfig","Login","Promote","Bootstrap","Configure","RefreshPricing","UpgradeSoftware","UpgradeGFlags","UpgradeCerts","UpgradeTLS","UpgradeVmImage","UpgradeSystemd","ResizeNode","AddMetrics","CreateKubernetes","SetupDocker","RetrieveKmsKey","RemoveKmsKeyReferenceHistory","UpsertCustomerFeatures","CreateSelfSignedCert","UpdateEmptyCustomerCertificate","GetRootCertificate","AddClientCertificate","SetDBCredentials","CreateUserInDB","SetHelm3Compatible","SetBackupFlag","SetUniverseKey","ResetUniverseVersion","ConfigUniverseAlert","ToggleTls","TlsConfigUpdate","UpdateDiskSize","CreateCluster","DeleteCluster","CreateAllClusters","UpdatePrimaryCluster","UpdateReadOnlyCluster","CreateReadOnlyCluster","DeleteReadOnlyCluster","RunYsqlQuery","BulkImport","CreateBackup","RestoreBackup","CreateSingleTableBackup","CreateMultiTableBackup","CreateBackupSchedule","EditBackupSchedule","StartPeriodicBackup","StopPeriodicBackup","DetachedNodeInstanceAction","NodeInstanceAction","DeleteBackupSchedule","ChangeUserRole","ChangeUserPassword","SetSecurity","GenerateApiToken","ResetSlowQueries","ExternalScriptSchedule","StopScheduledScript","UpdateScheduledScript","CreateInstanceType","DeleteInstanceType","GetUniverseResources"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		auditTypeActionPropEnum = append(auditTypeActionPropEnum, v)
	}
}

const (

	// AuditActionSet captures enum value "Set"
	AuditActionSet string = "Set"

	// AuditActionCreate captures enum value "Create"
	AuditActionCreate string = "Create"

	// AuditActionEdit captures enum value "Edit"
	AuditActionEdit string = "Edit"

	// AuditActionUpdate captures enum value "Update"
	AuditActionUpdate string = "Update"

	// AuditActionDelete captures enum value "Delete"
	AuditActionDelete string = "Delete"

	// AuditActionRegister captures enum value "Register"
	AuditActionRegister string = "Register"

	// AuditActionRefresh captures enum value "Refresh"
	AuditActionRefresh string = "Refresh"

	// AuditActionUpload captures enum value "Upload"
	AuditActionUpload string = "Upload"

	// AuditActionUpgrade captures enum value "Upgrade"
	AuditActionUpgrade string = "Upgrade"

	// AuditActionImport captures enum value "Import"
	AuditActionImport string = "Import"

	// AuditActionPause captures enum value "Pause"
	AuditActionPause string = "Pause"

	// AuditActionResume captures enum value "Resume"
	AuditActionResume string = "Resume"

	// AuditActionRestart captures enum value "Restart"
	AuditActionRestart string = "Restart"

	// AuditActionAbort captures enum value "Abort"
	AuditActionAbort string = "Abort"

	// AuditActionRetry captures enum value "Retry"
	AuditActionRetry string = "Retry"

	// AuditActionRestore captures enum value "Restore"
	AuditActionRestore string = "Restore"

	// AuditActionAlter captures enum value "Alter"
	AuditActionAlter string = "Alter"

	// AuditActionDrop captures enum value "Drop"
	AuditActionDrop string = "Drop"

	// AuditActionStop captures enum value "Stop"
	AuditActionStop string = "Stop"

	// AuditActionValidate captures enum value "Validate"
	AuditActionValidate string = "Validate"

	// AuditActionAcknowledge captures enum value "Acknowledge"
	AuditActionAcknowledge string = "Acknowledge"

	// AuditActionSyncXClusterConfig captures enum value "SyncXClusterConfig"
	AuditActionSyncXClusterConfig string = "SyncXClusterConfig"

	// AuditActionLogin captures enum value "Login"
	AuditActionLogin string = "Login"

	// AuditActionPromote captures enum value "Promote"
	AuditActionPromote string = "Promote"

	// AuditActionBootstrap captures enum value "Bootstrap"
	AuditActionBootstrap string = "Bootstrap"

	// AuditActionConfigure captures enum value "Configure"
	AuditActionConfigure string = "Configure"

	// AuditActionRefreshPricing captures enum value "RefreshPricing"
	AuditActionRefreshPricing string = "RefreshPricing"

	// AuditActionUpgradeSoftware captures enum value "UpgradeSoftware"
	AuditActionUpgradeSoftware string = "UpgradeSoftware"

	// AuditActionUpgradeGFlags captures enum value "UpgradeGFlags"
	AuditActionUpgradeGFlags string = "UpgradeGFlags"

	// AuditActionUpgradeCerts captures enum value "UpgradeCerts"
	AuditActionUpgradeCerts string = "UpgradeCerts"

	// AuditActionUpgradeTLS captures enum value "UpgradeTLS"
	AuditActionUpgradeTLS string = "UpgradeTLS"

	// AuditActionUpgradeVMImage captures enum value "UpgradeVmImage"
	AuditActionUpgradeVMImage string = "UpgradeVmImage"

	// AuditActionUpgradeSystemd captures enum value "UpgradeSystemd"
	AuditActionUpgradeSystemd string = "UpgradeSystemd"

	// AuditActionResizeNode captures enum value "ResizeNode"
	AuditActionResizeNode string = "ResizeNode"

	// AuditActionAddMetrics captures enum value "AddMetrics"
	AuditActionAddMetrics string = "AddMetrics"

	// AuditActionCreateKubernetes captures enum value "CreateKubernetes"
	AuditActionCreateKubernetes string = "CreateKubernetes"

	// AuditActionSetupDocker captures enum value "SetupDocker"
	AuditActionSetupDocker string = "SetupDocker"

	// AuditActionRetrieveKmsKey captures enum value "RetrieveKmsKey"
	AuditActionRetrieveKmsKey string = "RetrieveKmsKey"

	// AuditActionRemoveKmsKeyReferenceHistory captures enum value "RemoveKmsKeyReferenceHistory"
	AuditActionRemoveKmsKeyReferenceHistory string = "RemoveKmsKeyReferenceHistory"

	// AuditActionUpsertCustomerFeatures captures enum value "UpsertCustomerFeatures"
	AuditActionUpsertCustomerFeatures string = "UpsertCustomerFeatures"

	// AuditActionCreateSelfSignedCert captures enum value "CreateSelfSignedCert"
	AuditActionCreateSelfSignedCert string = "CreateSelfSignedCert"

	// AuditActionUpdateEmptyCustomerCertificate captures enum value "UpdateEmptyCustomerCertificate"
	AuditActionUpdateEmptyCustomerCertificate string = "UpdateEmptyCustomerCertificate"

	// AuditActionGetRootCertificate captures enum value "GetRootCertificate"
	AuditActionGetRootCertificate string = "GetRootCertificate"

	// AuditActionAddClientCertificate captures enum value "AddClientCertificate"
	AuditActionAddClientCertificate string = "AddClientCertificate"

	// AuditActionSetDBCredentials captures enum value "SetDBCredentials"
	AuditActionSetDBCredentials string = "SetDBCredentials"

	// AuditActionCreateUserInDB captures enum value "CreateUserInDB"
	AuditActionCreateUserInDB string = "CreateUserInDB"

	// AuditActionSetHelm3Compatible captures enum value "SetHelm3Compatible"
	AuditActionSetHelm3Compatible string = "SetHelm3Compatible"

	// AuditActionSetBackupFlag captures enum value "SetBackupFlag"
	AuditActionSetBackupFlag string = "SetBackupFlag"

	// AuditActionSetUniverseKey captures enum value "SetUniverseKey"
	AuditActionSetUniverseKey string = "SetUniverseKey"

	// AuditActionResetUniverseVersion captures enum value "ResetUniverseVersion"
	AuditActionResetUniverseVersion string = "ResetUniverseVersion"

	// AuditActionConfigUniverseAlert captures enum value "ConfigUniverseAlert"
	AuditActionConfigUniverseAlert string = "ConfigUniverseAlert"

	// AuditActionToggleTLS captures enum value "ToggleTls"
	AuditActionToggleTLS string = "ToggleTls"

	// AuditActionTLSConfigUpdate captures enum value "TlsConfigUpdate"
	AuditActionTLSConfigUpdate string = "TlsConfigUpdate"

	// AuditActionUpdateDiskSize captures enum value "UpdateDiskSize"
	AuditActionUpdateDiskSize string = "UpdateDiskSize"

	// AuditActionCreateCluster captures enum value "CreateCluster"
	AuditActionCreateCluster string = "CreateCluster"

	// AuditActionDeleteCluster captures enum value "DeleteCluster"
	AuditActionDeleteCluster string = "DeleteCluster"

	// AuditActionCreateAllClusters captures enum value "CreateAllClusters"
	AuditActionCreateAllClusters string = "CreateAllClusters"

	// AuditActionUpdatePrimaryCluster captures enum value "UpdatePrimaryCluster"
	AuditActionUpdatePrimaryCluster string = "UpdatePrimaryCluster"

	// AuditActionUpdateReadOnlyCluster captures enum value "UpdateReadOnlyCluster"
	AuditActionUpdateReadOnlyCluster string = "UpdateReadOnlyCluster"

	// AuditActionCreateReadOnlyCluster captures enum value "CreateReadOnlyCluster"
	AuditActionCreateReadOnlyCluster string = "CreateReadOnlyCluster"

	// AuditActionDeleteReadOnlyCluster captures enum value "DeleteReadOnlyCluster"
	AuditActionDeleteReadOnlyCluster string = "DeleteReadOnlyCluster"

	// AuditActionRunYsqlQuery captures enum value "RunYsqlQuery"
	AuditActionRunYsqlQuery string = "RunYsqlQuery"

	// AuditActionBulkImport captures enum value "BulkImport"
	AuditActionBulkImport string = "BulkImport"

	// AuditActionCreateBackup captures enum value "CreateBackup"
	AuditActionCreateBackup string = "CreateBackup"

	// AuditActionRestoreBackup captures enum value "RestoreBackup"
	AuditActionRestoreBackup string = "RestoreBackup"

	// AuditActionCreateSingleTableBackup captures enum value "CreateSingleTableBackup"
	AuditActionCreateSingleTableBackup string = "CreateSingleTableBackup"

	// AuditActionCreateMultiTableBackup captures enum value "CreateMultiTableBackup"
	AuditActionCreateMultiTableBackup string = "CreateMultiTableBackup"

	// AuditActionCreateBackupSchedule captures enum value "CreateBackupSchedule"
	AuditActionCreateBackupSchedule string = "CreateBackupSchedule"

	// AuditActionEditBackupSchedule captures enum value "EditBackupSchedule"
	AuditActionEditBackupSchedule string = "EditBackupSchedule"

	// AuditActionStartPeriodicBackup captures enum value "StartPeriodicBackup"
	AuditActionStartPeriodicBackup string = "StartPeriodicBackup"

	// AuditActionStopPeriodicBackup captures enum value "StopPeriodicBackup"
	AuditActionStopPeriodicBackup string = "StopPeriodicBackup"

	// AuditActionDetachedNodeInstanceAction captures enum value "DetachedNodeInstanceAction"
	AuditActionDetachedNodeInstanceAction string = "DetachedNodeInstanceAction"

	// AuditActionNodeInstanceAction captures enum value "NodeInstanceAction"
	AuditActionNodeInstanceAction string = "NodeInstanceAction"

	// AuditActionDeleteBackupSchedule captures enum value "DeleteBackupSchedule"
	AuditActionDeleteBackupSchedule string = "DeleteBackupSchedule"

	// AuditActionChangeUserRole captures enum value "ChangeUserRole"
	AuditActionChangeUserRole string = "ChangeUserRole"

	// AuditActionChangeUserPassword captures enum value "ChangeUserPassword"
	AuditActionChangeUserPassword string = "ChangeUserPassword"

	// AuditActionSetSecurity captures enum value "SetSecurity"
	AuditActionSetSecurity string = "SetSecurity"

	// AuditActionGenerateAPIToken captures enum value "GenerateApiToken"
	AuditActionGenerateAPIToken string = "GenerateApiToken"

	// AuditActionResetSlowQueries captures enum value "ResetSlowQueries"
	AuditActionResetSlowQueries string = "ResetSlowQueries"

	// AuditActionExternalScriptSchedule captures enum value "ExternalScriptSchedule"
	AuditActionExternalScriptSchedule string = "ExternalScriptSchedule"

	// AuditActionStopScheduledScript captures enum value "StopScheduledScript"
	AuditActionStopScheduledScript string = "StopScheduledScript"

	// AuditActionUpdateScheduledScript captures enum value "UpdateScheduledScript"
	AuditActionUpdateScheduledScript string = "UpdateScheduledScript"

	// AuditActionCreateInstanceType captures enum value "CreateInstanceType"
	AuditActionCreateInstanceType string = "CreateInstanceType"

	// AuditActionDeleteInstanceType captures enum value "DeleteInstanceType"
	AuditActionDeleteInstanceType string = "DeleteInstanceType"

	// AuditActionGetUniverseResources captures enum value "GetUniverseResources"
	AuditActionGetUniverseResources string = "GetUniverseResources"
)

// prop value enum
func (m *Audit) validateActionEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, auditTypeActionPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Audit) validateAction(formats strfmt.Registry) error {
	if swag.IsZero(m.Action) { // not required
		return nil
	}

	// value enum
	if err := m.validateActionEnum("action", "body", m.Action); err != nil {
		return err
	}

	return nil
}

func (m *Audit) validateAuditID(formats strfmt.Registry) error {

	if err := validate.Required("auditID", "body", m.AuditID); err != nil {
		return err
	}

	return nil
}

func (m *Audit) validateCustomerUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerUUID) { // not required
		return nil
	}

	if err := validate.FormatOf("customerUUID", "body", "uuid", m.CustomerUUID.String(), formats); err != nil {
		return err
	}

	return nil
}

var auditTypeTargetPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Session","CloudProvider","Region","AvailabilityZone","CustomerConfig","KMSConfig","Customer","Release","Certificate","Alert","AlertChannel","AlertDestination","MaintenanceWindow","AccessKey","Universe","XClusterConfig","Table","Backup","CustomerTask","NodeInstance","PlatformInstance","Schedule","User","LoggingConfig","RuntimeConfigKey","HAConfig","HABackup","ScheduledScript","SupportBundle","GFlags"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		auditTypeTargetPropEnum = append(auditTypeTargetPropEnum, v)
	}
}

const (

	// AuditTargetSession captures enum value "Session"
	AuditTargetSession string = "Session"

	// AuditTargetCloudProvider captures enum value "CloudProvider"
	AuditTargetCloudProvider string = "CloudProvider"

	// AuditTargetRegion captures enum value "Region"
	AuditTargetRegion string = "Region"

	// AuditTargetAvailabilityZone captures enum value "AvailabilityZone"
	AuditTargetAvailabilityZone string = "AvailabilityZone"

	// AuditTargetCustomerConfig captures enum value "CustomerConfig"
	AuditTargetCustomerConfig string = "CustomerConfig"

	// AuditTargetKMSConfig captures enum value "KMSConfig"
	AuditTargetKMSConfig string = "KMSConfig"

	// AuditTargetCustomer captures enum value "Customer"
	AuditTargetCustomer string = "Customer"

	// AuditTargetRelease captures enum value "Release"
	AuditTargetRelease string = "Release"

	// AuditTargetCertificate captures enum value "Certificate"
	AuditTargetCertificate string = "Certificate"

	// AuditTargetAlert captures enum value "Alert"
	AuditTargetAlert string = "Alert"

	// AuditTargetAlertChannel captures enum value "AlertChannel"
	AuditTargetAlertChannel string = "AlertChannel"

	// AuditTargetAlertDestination captures enum value "AlertDestination"
	AuditTargetAlertDestination string = "AlertDestination"

	// AuditTargetMaintenanceWindow captures enum value "MaintenanceWindow"
	AuditTargetMaintenanceWindow string = "MaintenanceWindow"

	// AuditTargetAccessKey captures enum value "AccessKey"
	AuditTargetAccessKey string = "AccessKey"

	// AuditTargetUniverse captures enum value "Universe"
	AuditTargetUniverse string = "Universe"

	// AuditTargetXClusterConfig captures enum value "XClusterConfig"
	AuditTargetXClusterConfig string = "XClusterConfig"

	// AuditTargetTable captures enum value "Table"
	AuditTargetTable string = "Table"

	// AuditTargetBackup captures enum value "Backup"
	AuditTargetBackup string = "Backup"

	// AuditTargetCustomerTask captures enum value "CustomerTask"
	AuditTargetCustomerTask string = "CustomerTask"

	// AuditTargetNodeInstance captures enum value "NodeInstance"
	AuditTargetNodeInstance string = "NodeInstance"

	// AuditTargetPlatformInstance captures enum value "PlatformInstance"
	AuditTargetPlatformInstance string = "PlatformInstance"

	// AuditTargetSchedule captures enum value "Schedule"
	AuditTargetSchedule string = "Schedule"

	// AuditTargetUser captures enum value "User"
	AuditTargetUser string = "User"

	// AuditTargetLoggingConfig captures enum value "LoggingConfig"
	AuditTargetLoggingConfig string = "LoggingConfig"

	// AuditTargetRuntimeConfigKey captures enum value "RuntimeConfigKey"
	AuditTargetRuntimeConfigKey string = "RuntimeConfigKey"

	// AuditTargetHAConfig captures enum value "HAConfig"
	AuditTargetHAConfig string = "HAConfig"

	// AuditTargetHABackup captures enum value "HABackup"
	AuditTargetHABackup string = "HABackup"

	// AuditTargetScheduledScript captures enum value "ScheduledScript"
	AuditTargetScheduledScript string = "ScheduledScript"

	// AuditTargetSupportBundle captures enum value "SupportBundle"
	AuditTargetSupportBundle string = "SupportBundle"

	// AuditTargetGFlags captures enum value "GFlags"
	AuditTargetGFlags string = "GFlags"
)

// prop value enum
func (m *Audit) validateTargetEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, auditTypeTargetPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Audit) validateTarget(formats strfmt.Registry) error {
	if swag.IsZero(m.Target) { // not required
		return nil
	}

	// value enum
	if err := m.validateTargetEnum("target", "body", m.Target); err != nil {
		return err
	}

	return nil
}

func (m *Audit) validateTaskUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.TaskUUID) { // not required
		return nil
	}

	if err := validate.FormatOf("taskUUID", "body", "uuid", m.TaskUUID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Audit) validateTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("timestamp", "body", m.Timestamp); err != nil {
		return err
	}

	if err := validate.FormatOf("timestamp", "body", "date-time", m.Timestamp.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Audit) validateUserUUID(formats strfmt.Registry) error {
	if swag.IsZero(m.UserUUID) { // not required
		return nil
	}

	if err := validate.FormatOf("userUUID", "body", "uuid", m.UserUUID.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this audit based on the context it is used
func (m *Audit) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAction(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAPICall(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAPIMethod(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerUUID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTarget(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTargetID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTaskUUID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUserEmail(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUserUUID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Audit) contextValidateAction(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "action", "body", string(m.Action)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateAPICall(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "apiCall", "body", string(m.APICall)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateAPIMethod(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "apiMethod", "body", string(m.APIMethod)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateCustomerUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "customerUUID", "body", strfmt.UUID(m.CustomerUUID)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateTarget(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "target", "body", string(m.Target)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateTargetID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "targetID", "body", string(m.TargetID)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateTaskUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "taskUUID", "body", strfmt.UUID(m.TaskUUID)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateUserEmail(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "userEmail", "body", string(m.UserEmail)); err != nil {
		return err
	}

	return nil
}

func (m *Audit) contextValidateUserUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "userUUID", "body", strfmt.UUID(m.UserUUID)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Audit) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Audit) UnmarshalBinary(b []byte) error {
	var res Audit
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
