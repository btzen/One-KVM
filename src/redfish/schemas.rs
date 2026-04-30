use serde::{Deserialize, Serialize};
use serde_json::Value;

fn odata_ref(id: &str) -> ODataLink {
    ODataLink {
        odata_id: id.to_string(),
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ODataLink {
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub State: String,
    pub Health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub HealthRollup: Option<String>,
}

impl Status {
    pub fn enabled_ok() -> Self {
        Self {
            State: "Enabled".to_string(),
            Health: "OK".to_string(),
            HealthRollup: None,
        }
    }

    pub fn enabled_health(health: &str) -> Self {
        Self {
            State: "Enabled".to_string(),
            Health: health.to_string(),
            HealthRollup: None,
        }
    }

    pub fn disabled_ok() -> Self {
        Self {
            State: "Disabled".to_string(),
            Health: "OK".to_string(),
            HealthRollup: None,
        }
    }

    pub fn offline_ok() -> Self {
        Self {
            State: "Offline".to_string(),
            Health: "OK".to_string(),
            HealthRollup: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceRoot {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub RedfishVersion: String,
    pub UUID: String,
    pub ProtocolFeaturesSupported: ProtocolFeaturesSupported,
    pub Systems: ODataLink,
    pub Chassis: ODataLink,
    pub Managers: ODataLink,
    pub SessionService: ODataLink,
    pub AccountService: ODataLink,
    pub EventService: ODataLink,
    pub Links: ServiceRootLinks,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProtocolFeaturesSupported {
    pub ExcerptQuery: bool,
    pub ExpandQuery: ExpandQuery,
    pub FilterQuery: bool,
    pub OnlyMemberQuery: bool,
    pub SelectQuery: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpandQuery {
    pub ExpandAll: bool,
    pub Levels: bool,
    pub MaxLevels: u32,
    pub NoLinks: bool,
    pub Top: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceRootLinks {
    pub Sessions: ODataLink,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Collection<T: Serialize> {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Name: String,
    pub Description: String,
    #[serde(rename = "Members@odata.count")]
    pub members_count: u64,
    pub Members: Vec<T>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerSystem {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    #[serde(rename = "@odata.etag")]
    pub odata_etag: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub SystemType: String,
    pub AssetTag: String,
    pub Manufacturer: String,
    pub Model: String,
    pub SerialNumber: String,
    pub PartNumber: String,
    pub PowerState: String,
    pub BiosVersion: String,
    pub Status: Status,
    pub Boot: Boot,
    pub ProcessorSummary: ProcessorSummary,
    pub MemorySummary: MemorySummary,
    pub TrustedModules: Vec<Value>,
    pub Actions: ComputerSystemActions,
    pub Links: ComputerSystemLinks,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Boot {
    pub BootSourceOverrideEnabled: String,
    pub BootSourceOverrideMode: Option<String>,
    pub BootSourceOverrideTarget: Option<String>,
    pub UefiTargetBootSourceOverride: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProcessorSummary {
    pub Count: Option<u32>,
    pub LogicalProcessorCount: Option<u32>,
    pub Model: String,
    pub Status: Status,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MemorySummary {
    pub TotalSystemMemoryGiB: Option<f64>,
    pub Status: Status,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerSystemActions {
    #[serde(rename = "#ComputerSystem.Reset")]
    pub reset: ActionTarget,
    #[serde(rename = "#ComputerSystem.SetDefaultBootOrder")]
    pub set_default_boot_order: ActionTarget,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionTarget {
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerSystemLinks {
    pub Chassis: Vec<ODataLink>,
    pub ManagedBy: Vec<ODataLink>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResetRequest {
    #[serde(default = "default_reset_type")]
    pub ResetType: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComputerSystemPatchRequest {
    #[serde(default)]
    pub Boot: Option<BootPatch>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootPatch {
    #[serde(default)]
    pub BootSourceOverrideEnabled: Option<String>,
    #[serde(default)]
    pub BootSourceOverrideTarget: Option<String>,
    #[serde(default)]
    pub BootSourceOverrideMode: Option<String>,
    #[serde(default)]
    pub UefiTargetBootSourceOverride: Option<String>,
}

fn default_reset_type() -> String {
    "ForceRestart".to_string()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Manager {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub ManagerType: String,
    pub Status: Status,
    pub FirmwareVersion: String,
    pub Manufacturer: String,
    pub Model: String,
    pub DateTime: String,
    pub DateTimeLocalOffset: String,
    pub ServiceEntryPointUUID: String,
    pub CommandShell: CommandShell,
    pub GraphicalConsole: GraphicalConsole,
    pub VirtualMedia: ODataLink,
    pub Links: ManagerLinks,
    pub NetworkProtocol: ODataLink,
    pub EthernetInterfaces: ODataLink,
    pub LogServices: ODataLink,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CommandShell {
    pub ServiceEnabled: bool,
    pub MaxConcurrentSessions: u32,
    pub ConnectTypesSupported: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GraphicalConsole {
    pub ServiceEnabled: bool,
    pub MaxConcurrentSessions: u32,
    pub ConnectTypesSupported: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ManagerLinks {
    pub ManagerForServers: Vec<ODataLink>,
    pub ManagerForChassis: Vec<ODataLink>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct VirtualMedia {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub MediaTypes: Vec<String>,
    pub ConnectedVia: Option<String>,
    pub Inserted: bool,
    pub Image: Option<String>,
    pub ImageName: Option<String>,
    pub WriteProtected: bool,
    pub TransferMethod: Option<String>,
    pub TransferProtocolType: Option<String>,
    pub Status: Status,
    pub Actions: VirtualMediaActions,
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualMediaActions {
    #[serde(rename = "#VirtualMedia.InsertMedia")]
    pub insert_media: ActionTarget,
    #[serde(rename = "#VirtualMedia.EjectMedia")]
    pub eject_media: ActionTarget,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InsertMediaRequest {
    pub Image: String,
    #[serde(default)]
    pub WriteProtected: Option<bool>,
    #[serde(default)]
    pub TransferMethod: Option<String>,
    #[serde(default)]
    pub TransferProtocolType: Option<String>,
    pub MediaTypes: Option<Vec<String>>,
    pub Inserted: Option<bool>,
    pub UserName: Option<String>,
    pub Password: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Chassis {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub ChassisType: String,
    pub AssetTag: String,
    pub Manufacturer: String,
    pub Model: String,
    pub SerialNumber: String,
    pub PartNumber: String,
    pub PowerState: String,
    pub Status: Status,
    pub Thermal: ODataLink,
    pub Power: ODataLink,
    pub Links: ChassisLinks,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChassisLinks {
    pub ComputerSystems: Vec<ODataLink>,
    pub ManagedBy: Vec<ODataLink>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Power {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub PowerControl: Vec<PowerControl>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowerControl {
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    pub MemberId: String,
    pub Name: String,
    pub PowerConsumedWatts: Option<f64>,
    pub PowerCapacityWatts: Option<f64>,
    pub PowerRequestedWatts: Option<f64>,
    pub PowerMetrics: Option<PowerMetric>,
    pub Status: Status,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowerMetric {
    pub IntervalInMin: u32,
    pub MinConsumedWatts: Option<f64>,
    pub MaxConsumedWatts: Option<f64>,
    pub AverageConsumedWatts: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SessionService {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub ServiceEnabled: bool,
    pub SessionTimeout: String,
    pub Sessions: ODataLink,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Session {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub UserName: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionCreateRequest {
    pub UserName: String,
    pub Password: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AccountService {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub ServiceEnabled: bool,
    pub Accounts: ODataLink,
    pub Roles: ODataLink,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ManagerAccount {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub Enabled: bool,
    pub UserName: String,
    pub RoleId: String,
    pub Locked: bool,
    pub Links: ManagerAccountLinks,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ManagerAccountLinks {
    pub Role: ODataLink,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventService {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub Id: String,
    pub Name: String,
    pub Description: String,
    pub ServiceEnabled: bool,
    pub DeliveryRetryAttempts: u32,
    pub DeliveryRetryIntervalSeconds: u32,
    pub EventFormatTypes: Vec<String>,
    pub RegistryPrefixes: Vec<String>,
    pub SubordinateResources: bool,
    pub SSEFilterPropertiesSupported: SseFilterPropertiesSupported,
    pub Subscriptions: ODataLink,
    pub Actions: EventServiceActions,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SseFilterPropertiesSupported {
    pub EventFormatType: bool,
    pub MessageId: bool,
    pub MetricReportDefinition: bool,
    pub OriginResource: bool,
    pub RegistryPrefix: bool,
    pub ResourceType: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventServiceActions {
    #[serde(rename = "#EventService.SubmitTestEvent")]
    pub submit_test_event: ActionTarget,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedfishError {
    pub error: RedfishErrorBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedfishErrorBody {
    pub code: String,
    pub message: String,
    #[serde(rename = "@Message.ExtendedInfo", skip_serializing_if = "Vec::is_empty")]
    pub extended_info: Vec<RedfishExtendedInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedfishExtendedInfo {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    pub MessageId: String,
    pub Message: String,
    pub Severity: String,
    pub Resolution: String,
}

impl RedfishError {
    pub fn general_error(message: &str) -> Self {
        Self {
            error: RedfishErrorBody {
                code: "Base.1.18.GeneralError".to_string(),
                message: message.to_string(),
                extended_info: vec![],
            },
        }
    }

    pub fn authentication_required() -> Self {
        Self {
            error: RedfishErrorBody {
                code: "Base.1.18.AuthenticationRequired".to_string(),
                message: "Authentication is required to access this resource".to_string(),
                extended_info: vec![RedfishExtendedInfo {
                    odata_type: "#Message.v1_2_1.Message".to_string(),
                    MessageId: "Base.1.18.AuthenticationRequired".to_string(),
                    Message: "Authentication is required to access this resource".to_string(),
                    Severity: "Critical".to_string(),
                    Resolution: "Authenticate using HTTP Basic auth or create a session via POST /redfish/v1/SessionService/Sessions".to_string(),
                }],
            },
        }
    }

    pub fn invalid_credentials() -> Self {
        Self {
            error: RedfishErrorBody {
                code: "Base.1.18.AuthenticationRequired".to_string(),
                message: "Invalid username or password".to_string(),
                extended_info: vec![RedfishExtendedInfo {
                    odata_type: "#Message.v1_2_1.Message".to_string(),
                    MessageId: "Base.1.18.InvalidCredentials".to_string(),
                    Message: "Invalid username or password".to_string(),
                    Severity: "Critical".to_string(),
                    Resolution: "Correct the credentials and retry".to_string(),
                }],
            },
        }
    }

    pub fn resource_not_found() -> Self {
        Self {
            error: RedfishErrorBody {
                code: "Base.1.18.ResourceNotFound".to_string(),
                message: "The requested resource was not found".to_string(),
                extended_info: vec![],
            },
        }
    }

    pub fn action_not_supported(action: &str) -> Self {
        Self {
            error: RedfishErrorBody {
                code: "Base.1.18.ActionNotSupported".to_string(),
                message: format!("Action '{}' is not supported", action),
                extended_info: vec![],
            },
        }
    }

    pub fn property_missing(property: &str) -> Self {
        Self {
            error: RedfishErrorBody {
                code: "Base.1.18.PropertyMissing".to_string(),
                message: format!("Property '{}' is required", property),
                extended_info: vec![],
            },
        }
    }

    pub fn service_unavailable(msg: &str) -> Self {
        Self {
            error: RedfishErrorBody {
                code: "Base.1.18.ServiceUnavailable".to_string(),
                message: msg.to_string(),
                extended_info: vec![],
            },
        }
    }
}
