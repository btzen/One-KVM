use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get, patch, post},
    Json, Router,
};
use futures::stream::Stream;
use serde_json::json;
use std::{convert::Infallible, pin::Pin, sync::Arc, time::Duration};
use tracing::{info, warn};

use super::auth::redfish_auth_middleware;
use super::schemas::*;
use crate::state::AppState;

const REDFISH_VERSION: &str = "1.18.1";
const SYSTEM_ID: &str = "1";
const CHASSIS_ID: &str = "1";
const MANAGER_ID: &str = "1";
const VIRTUAL_MEDIA_ID: &str = "1";

pub fn create_redfish_router(state: Arc<AppState>) -> Router {
    let redfish_routes = Router::new()
        .route("/", get(service_root))
        .route("/v1", get(service_root_redirect))
        .route("/v1/", get(service_root))
        .route("/v1/odata", get(odata_document))
        .route("/v1/$metadata", get(metadata))
        .route("/v1/Systems", get(systems_collection))
        .route("/v1/Systems/{system_id}", get(system_detail).patch(system_patch))
        .route(
            "/v1/Systems/{system_id}/Actions/ComputerSystem.Reset",
            post(system_reset),
        )
        .route("/v1/Chassis", get(chassis_collection))
        .route("/v1/Chassis/{chassis_id}", get(chassis_detail))
        .route("/v1/Chassis/{chassis_id}/Power", get(chassis_power))
        .route("/v1/Managers", get(managers_collection))
        .route("/v1/Managers/{manager_id}", get(manager_detail))
        .route(
            "/v1/Managers/{manager_id}/VirtualMedia",
            get(virtual_media_collection),
        )
        .route(
            "/v1/Managers/{manager_id}/VirtualMedia/{media_id}",
            get(virtual_media_detail),
        )
        .route(
            "/v1/Managers/{manager_id}/VirtualMedia/{media_id}/Actions/VirtualMedia.InsertMedia",
            post(virtual_media_insert),
        )
        .route(
            "/v1/Managers/{manager_id}/VirtualMedia/{media_id}/Actions/VirtualMedia.EjectMedia",
            post(virtual_media_eject),
        )
        .route("/v1/SessionService", get(session_service))
        .route(
            "/v1/SessionService/Sessions",
            get(session_list).post(session_create),
        )
        .route(
            "/v1/SessionService/Sessions/{session_id}",
            delete(session_delete),
        )
        .route("/v1/AccountService", get(account_service))
        .route(
            "/v1/AccountService/Accounts",
            get(account_list),
        )
        .route(
            "/v1/AccountService/Accounts/{account_id}",
            get(account_detail),
        )
        .route("/v1/EventService", get(event_service))
        .route("/v1/EventService/SSE", get(event_service_sse))
        .route(
            "/v1/EventService/Actions/EventService.SubmitTestEvent",
            post(event_submit_test),
        )
        .route("/v1/EventService/Subscriptions", get(event_subscriptions_stub))
        .route("/v1/Chassis/{chassis_id}/Thermal", get(thermal_stub))
        .route("/v1/Managers/{manager_id}/NetworkProtocol", get(network_protocol_stub))
        .route("/v1/Managers/{manager_id}/EthernetInterfaces", get(ethernet_interfaces_stub))
        .route("/v1/Managers/{manager_id}/LogServices", get(log_services_stub))
        .route("/v1/AccountService/Roles", get(roles_stub))
        .route("/v1/AccountService/Roles/{role_id}", get(role_detail_stub))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            redfish_auth_middleware,
        ));

    Router::new()
        .route("/redfish", get(service_root_redirect))
        .nest("/redfish", redfish_routes)
        .with_state(state)
}

async fn service_root_redirect() -> Response {
    axum::response::Redirect::permanent("/redfish/v1/").into_response()
}

fn service_root_static(uuid: &str) -> ServiceRoot {
    ServiceRoot {
        odata_type: "#ServiceRoot.v1_17_0.ServiceRoot".to_string(),
        odata_id: "/redfish/v1".to_string(),
        odata_context: "/redfish/v1/$metadata#ServiceRoot.ServiceRoot".to_string(),
        Id: "RootService".to_string(),
        Name: "One-KVM Redfish Service".to_string(),
        RedfishVersion: REDFISH_VERSION.to_string(),
        UUID: uuid.to_string(),
        ProtocolFeaturesSupported: ProtocolFeaturesSupported {
            ExcerptQuery: false,
            ExpandQuery: ExpandQuery {
                ExpandAll: false,
                Levels: false,
                MaxLevels: 0,
                NoLinks: false,
                Top: false,
            },
            FilterQuery: false,
            OnlyMemberQuery: true,
            SelectQuery: false,
        },
        Systems: odata_ref("/redfish/v1/Systems"),
        Chassis: odata_ref("/redfish/v1/Chassis"),
        Managers: odata_ref("/redfish/v1/Managers"),
        SessionService: odata_ref("/redfish/v1/SessionService"),
        AccountService: odata_ref("/redfish/v1/AccountService"),
        EventService: odata_ref("/redfish/v1/EventService"),
        Links: ServiceRootLinks {
            Sessions: odata_ref("/redfish/v1/SessionService/Sessions"),
        },
    }
}

async fn service_root(State(state): State<Arc<AppState>>) -> Json<ServiceRoot> {
    let config = state.config.get();
    let uuid = format!("one-kvm-{}", config.video.device.as_deref().unwrap_or("default"));
    Json(service_root_static(&uuid))
}

async fn odata_document() -> Json<serde_json::Value> {
    Json(json!({
        "@odata.context": "/redfish/v1/$metadata",
        "value": [
            {
                "name": "ServiceRoot",
                "kind": "Singleton",
                "url": "/redfish/v1"
            },
            {
                "name": "Systems",
                "kind": "Collection",
                "url": "/redfish/v1/Systems"
            },
            {
                "name": "Chassis",
                "kind": "Collection",
                "url": "/redfish/v1/Chassis"
            },
            {
                "name": "Managers",
                "kind": "Collection",
                "url": "/redfish/v1/Managers"
            }
        ]
    }))
}

async fn metadata() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/ServiceRoot_v1.xml">
    <edmx:Include Namespace="ServiceRoot"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/ComputerSystem_v1.xml">
    <edmx:Include Namespace="ComputerSystem"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/Manager_v1.xml">
    <edmx:Include Namespace="Manager"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/Chassis_v1.xml">
    <edmx:Include Namespace="Chassis"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/Power_v1.xml">
    <edmx:Include Namespace="Power"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/VirtualMedia_v1.xml">
    <edmx:Include Namespace="VirtualMedia"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/SessionService_v1.xml">
    <edmx:Include Namespace="SessionService"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/AccountService_v1.xml">
    <edmx:Include Namespace="AccountService"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/EventService_v1.xml">
    <edmx:Include Namespace="EventService"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/Thermal_v1.xml">
    <edmx:Include Namespace="Thermal"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/ManagerNetworkProtocol_v1.xml">
    <edmx:Include Namespace="ManagerNetworkProtocol"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/Role_v1.xml">
    <edmx:Include Namespace="Role"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://docs.oasis-open.org/odata/ns/edm">
    <edmx:Include Namespace="Edm" />
  </edmx:Reference>
  <edmx:DataServices>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="OneKVM">
      <EntityContainer Name="Service" Extends="ServiceRoot.v1_17_0.ServiceContainer"/>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#.to_string()
}

async fn systems_collection() -> Json<Collection<ODataLink>> {
    Json(Collection {
        odata_type: "#ComputerSystemCollection.ComputerSystemCollection".to_string(),
        odata_id: "/redfish/v1/Systems".to_string(),
        odata_context: "/redfish/v1/$metadata#ComputerSystemCollection.ComputerSystemCollection"
            .to_string(),
        Name: "Computer System Collection".to_string(),
        Description: "Collection of Computer Systems".to_string(),
        members_count: 1,
        Members: vec![odata_ref("/redfish/v1/Systems/1")],
    })
}

async fn system_detail(
    State(state): State<Arc<AppState>>,
    Path(system_id): Path<String>,
) -> Response {
    if system_id != SYSTEM_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let (power_state, atx_state) = {
        let atx_guard = state.atx.read().await;
        match atx_guard.as_ref() {
            Some(atx) => {
                let ps = atx.power_status().await;
                let ps_str = match ps {
                    crate::atx::PowerStatus::On => "On",
                    crate::atx::PowerStatus::Off => "Off",
                    crate::atx::PowerStatus::Unknown => "On",
                };
                let state = atx.state().await;
                (ps_str.to_string(), state)
            }
            None => ("On".to_string(), crate::atx::AtxState::default()),
        }
    };

    let system = ComputerSystem {
        odata_type: "#ComputerSystem.v1_20_0.ComputerSystem".to_string(),
        odata_id: format!("/redfish/v1/Systems/{}", system_id),
        odata_context: "/redfish/v1/$metadata#ComputerSystem.ComputerSystem".to_string(),
        odata_etag: format!("W/\"{}\"", uuid::Uuid::new_v4()),
        Id: system_id.clone(),
        Name: "Managed System".to_string(),
        Description: "The managed computer system connected via One-KVM".to_string(),
        SystemType: "Physical".to_string(),
        AssetTag: String::new(),
        Manufacturer: "Unknown".to_string(),
        Model: "Unknown".to_string(),
        SerialNumber: String::new(),
        PartNumber: String::new(),
        PowerState: power_state,
        BiosVersion: "Unknown".to_string(),
        Status: Status::enabled_ok(),
        Boot: Boot {
            BootSourceOverrideEnabled: "Disabled".to_string(),
            BootSourceOverrideMode: None,
            BootSourceOverrideTarget: None,
            UefiTargetBootSourceOverride: None,
        },
        ProcessorSummary: ProcessorSummary {
            Count: None,
            LogicalProcessorCount: None,
            Model: "Unknown".to_string(),
            Status: Status::enabled_ok(),
        },
        MemorySummary: MemorySummary {
            TotalSystemMemoryGiB: None,
            Status: Status::enabled_ok(),
        },
        TrustedModules: vec![],
        Actions: ComputerSystemActions {
            reset: ActionTarget {
                target: format!(
                    "/redfish/v1/Systems/{}/Actions/ComputerSystem.Reset",
                    system_id
                ),
            },
            set_default_boot_order: ActionTarget {
                target: format!(
                    "/redfish/v1/Systems/{}/Actions/ComputerSystem.SetDefaultBootOrder",
                    system_id
                ),
            },
        },
        Links: ComputerSystemLinks {
            Chassis: vec![odata_ref("/redfish/v1/Chassis/1")],
            ManagedBy: vec![odata_ref("/redfish/v1/Managers/1")],
        },
    };

    Json(system).into_response()
}

async fn system_reset(
    State(state): State<Arc<AppState>>,
    Path(system_id): Path<String>,
    Json(req): Json<ResetRequest>,
) -> Response {
    if system_id != SYSTEM_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let atx_guard = state.atx.read().await;
    match atx_guard.as_ref() {
        Some(atx) => {
            let result = match req.ResetType.as_str() {
                "On" => {
                    atx.power_short().await
                }
                "ForceOff" | "GracefulShutdown" => {
                    atx.power_long().await
                }
                "ForceRestart" | "GracefulRestart" | "PowerCycle" => {
                    atx.reset().await
                }
                "PushPowerButton" => {
                    atx.power_short().await
                },
                "Nmi" => {
                    let body = RedfishError::action_not_supported("Nmi");
                    return (StatusCode::NOT_ACCEPTABLE, Json(body)).into_response();
                }
                _ => {
                    let body = RedfishError::action_not_supported(&req.ResetType);
                    return (StatusCode::NOT_ACCEPTABLE, Json(body)).into_response();
                }
            };

            match result {
                Ok(()) => {
                    info!("Redfish: System reset '{}' executed", req.ResetType);
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(e) => {
                    warn!("Redfish: System reset failed: {}", e);
                    let body = RedfishError::general_error(&e.to_string());
                    (StatusCode::BAD_REQUEST, Json(body)).into_response()
                }
            }
        }
        None => {
            let body = RedfishError::service_unavailable("ATX power control not available");
            (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
        }
    }
}

async fn chassis_collection() -> Json<Collection<ODataLink>> {
    Json(Collection {
        odata_type: "#ChassisCollection.ChassisCollection".to_string(),
        odata_id: "/redfish/v1/Chassis".to_string(),
        odata_context: "/redfish/v1/$metadata#ChassisCollection.ChassisCollection".to_string(),
        Name: "Chassis Collection".to_string(),
        Description: "Collection of Chassis".to_string(),
        members_count: 1,
        Members: vec![odata_ref("/redfish/v1/Chassis/1")],
    })
}

async fn chassis_detail(
    State(state): State<Arc<AppState>>,
    Path(chassis_id): Path<String>,
) -> Response {
    if chassis_id != CHASSIS_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let power_state = {
        let atx_guard = state.atx.read().await;
        match atx_guard.as_ref() {
            Some(atx) => match atx.power_status().await {
                crate::atx::PowerStatus::On => "On",
                crate::atx::PowerStatus::Off => "Off",
                crate::atx::PowerStatus::Unknown => "On",
            },
            None => "On",
        }
    };

    let chassis = Chassis {
        odata_type: "#Chassis.v1_25_0.Chassis".to_string(),
        odata_id: format!("/redfish/v1/Chassis/{}", chassis_id),
        odata_context: "/redfish/v1/$metadata#Chassis.Chassis".to_string(),
        Id: chassis_id.clone(),
        Name: "One-KVM Chassis".to_string(),
        Description: "The physical chassis managed by One-KVM".to_string(),
        ChassisType: "RackMount".to_string(),
        AssetTag: String::new(),
        Manufacturer: "One-KVM".to_string(),
        Model: "Virtual".to_string(),
        SerialNumber: String::new(),
        PartNumber: String::new(),
        PowerState: power_state.to_string(),
        Status: Status::enabled_ok(),
        Thermal: odata_ref(&format!("/redfish/v1/Chassis/{}/Thermal", chassis_id)),
        Power: odata_ref(&format!("/redfish/v1/Chassis/{}/Power", chassis_id)),
        Links: ChassisLinks {
            ComputerSystems: vec![odata_ref("/redfish/v1/Systems/1")],
            ManagedBy: vec![odata_ref("/redfish/v1/Managers/1")],
        },
    };

    Json(chassis).into_response()
}

async fn chassis_power(
    State(state): State<Arc<AppState>>,
    Path(chassis_id): Path<String>,
) -> Response {
    if chassis_id != CHASSIS_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let power_state = {
        let atx_guard = state.atx.read().await;
        match atx_guard.as_ref() {
            Some(atx) => match atx.power_status().await {
                crate::atx::PowerStatus::On => "On",
                crate::atx::PowerStatus::Off => "Off",
                crate::atx::PowerStatus::Unknown => "On",
            },
            None => "Unknown",
        }
    };

    let power = Power {
        odata_type: "#Power.v1_7_3.Power".to_string(),
        odata_id: format!("/redfish/v1/Chassis/{}/Power", chassis_id),
        odata_context: "/redfish/v1/$metadata#Power.Power".to_string(),
        Id: "Power".to_string(),
        Name: "Power".to_string(),
        PowerControl: vec![PowerControl {
            odata_id: format!("/redfish/v1/Chassis/{}/Power#/PowerControl/0", chassis_id),
            MemberId: "0".to_string(),
            Name: "System Power Control".to_string(),
            PowerConsumedWatts: None,
            PowerCapacityWatts: None,
            PowerRequestedWatts: None,
            PowerMetrics: None,
            Status: Status::enabled_health(power_state),
        }],
    };

    Json(power).into_response()
}

async fn managers_collection() -> Json<Collection<ODataLink>> {
    Json(Collection {
        odata_type: "#ManagerCollection.ManagerCollection".to_string(),
        odata_id: "/redfish/v1/Managers".to_string(),
        odata_context: "/redfish/v1/$metadata#ManagerCollection.ManagerCollection".to_string(),
        Name: "Manager Collection".to_string(),
        Description: "Collection of Managers".to_string(),
        members_count: 1,
        Members: vec![odata_ref("/redfish/v1/Managers/1")],
    })
}

async fn manager_detail(
    State(state): State<Arc<AppState>>,
    Path(manager_id): Path<String>,
) -> Response {
    if manager_id != MANAGER_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let config = state.config.get();
    let now = time::OffsetDateTime::now_utc();
    let datetime = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let local_offset = now.offset();
    let offset_str = format!("{:+03}{:02}", local_offset.whole_hours(), local_offset.minutes_past_hour().abs());

    let msd_available = state.msd.read().await.is_some();

    let manager = Manager {
        odata_type: "#Manager.v1_15_0.Manager".to_string(),
        odata_id: format!("/redfish/v1/Managers/{}", manager_id),
        odata_context: "/redfish/v1/$metadata#Manager.Manager".to_string(),
        Id: manager_id.clone(),
        Name: "One-KVM Manager".to_string(),
        Description: "One-KVM Management Controller".to_string(),
        ManagerType: "BMC".to_string(),
        Status: Status::enabled_ok(),
        FirmwareVersion: env!("CARGO_PKG_VERSION").to_string(),
        Manufacturer: "One-KVM".to_string(),
        Model: "One-KVM".to_string(),
        DateTime: datetime,
        DateTimeLocalOffset: offset_str,
        ServiceEntryPointUUID: format!("one-kvm-mgr-{}", manager_id),
        CommandShell: CommandShell {
            ServiceEnabled: state.extensions.check_available(crate::extensions::ExtensionId::Ttyd),
            MaxConcurrentSessions: 1,
            ConnectTypesSupported: vec!["WebUI".to_string()],
        },
        GraphicalConsole: GraphicalConsole {
            ServiceEnabled: true,
            MaxConcurrentSessions: 4,
            ConnectTypesSupported: vec!["KVMIP".to_string()],
        },
        VirtualMedia: odata_ref(&format!(
            "/redfish/v1/Managers/{}/VirtualMedia",
            manager_id
        )),
        Links: ManagerLinks {
            ManagerForServers: vec![odata_ref("/redfish/v1/Systems/1")],
            ManagerForChassis: vec![odata_ref("/redfish/v1/Chassis/1")],
        },
        NetworkProtocol: odata_ref(&format!(
            "/redfish/v1/Managers/{}/NetworkProtocol",
            manager_id
        )),
        EthernetInterfaces: odata_ref(&format!(
            "/redfish/v1/Managers/{}/EthernetInterfaces",
            manager_id
        )),
        LogServices: odata_ref(&format!(
            "/redfish/v1/Managers/{}/LogServices",
            manager_id
        )),
    };

    Json(manager).into_response()
}

async fn virtual_media_collection(
    State(state): State<Arc<AppState>>,
    Path(manager_id): Path<String>,
) -> Response {
    if manager_id != MANAGER_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let collection = Collection {
        odata_type: "#VirtualMediaCollection.VirtualMediaCollection".to_string(),
        odata_id: format!("/redfish/v1/Managers/{}/VirtualMedia", manager_id),
        odata_context: "/redfish/v1/$metadata#VirtualMediaCollection.VirtualMediaCollection"
            .to_string(),
        Name: "Virtual Media Collection".to_string(),
        Description: "Collection of Virtual Media".to_string(),
        members_count: 1,
        Members: vec![odata_ref(&format!(
            "/redfish/v1/Managers/{}/VirtualMedia/{}",
            manager_id, VIRTUAL_MEDIA_ID
        ))],
    };

    Json(collection).into_response()
}

async fn virtual_media_detail(
    State(state): State<Arc<AppState>>,
    Path((manager_id, media_id)): Path<(String, String)>,
) -> Response {
    if manager_id != MANAGER_ID || media_id != VIRTUAL_MEDIA_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let (inserted, image_name, connected_via) = {
        let msd_guard = state.msd.read().await;
        match msd_guard.as_ref() {
            Some(msd) => {
                let msd_state = msd.state().await;
                let img_name = msd_state
                    .current_image
                    .as_ref()
                    .map(|i| i.name.clone())
                    .or_else(|| {
                        msd_state
                            .drive_info
                            .as_ref()
                            .map(|_| "Virtual Drive".to_string())
                    });
                (
                    msd_state.connected,
                    img_name,
                    if msd_state.connected {
                        Some("Applet".to_string())
                    } else {
                        None
                    },
                )
            }
            None => (false, None, None),
        }
    };

    let vm = VirtualMedia {
        odata_type: "#VirtualMedia.v1_6_2.VirtualMedia".to_string(),
        odata_id: format!(
            "/redfish/v1/Managers/{}/VirtualMedia/{}",
            manager_id, media_id
        ),
        odata_context: "/redfish/v1/$metadata#VirtualMedia.VirtualMedia".to_string(),
        Id: media_id.clone(),
        Name: "Virtual Media 1".to_string(),
        Description: "Virtual Media Device".to_string(),
        MediaTypes: vec!["CD".to_string(), "USBStick".to_string()],
        ConnectedVia: connected_via,
        Inserted: inserted,
        Image: None,
        ImageName: image_name,
        WriteProtected: true,
        TransferMethod: None,
        TransferProtocolType: None,
        Status: if inserted {
            Status::enabled_ok()
        } else {
            Status::disabled_ok()
        },
        Actions: VirtualMediaActions {
            insert_media: ActionTarget {
                target: format!(
                    "/redfish/v1/Managers/{}/VirtualMedia/{}/Actions/VirtualMedia.InsertMedia",
                    manager_id, media_id
                ),
            },
            eject_media: ActionTarget {
                target: format!(
                    "/redfish/v1/Managers/{}/VirtualMedia/{}/Actions/VirtualMedia.EjectMedia",
                    manager_id, media_id
                ),
            },
        },
    };

    Json(vm).into_response()
}

async fn virtual_media_insert(
    State(state): State<Arc<AppState>>,
    Path((manager_id, media_id)): Path<(String, String)>,
    Json(_req): Json<InsertMediaRequest>,
) -> Response {
    if manager_id != MANAGER_ID || media_id != VIRTUAL_MEDIA_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let msd_guard = state.msd.read().await;
    match msd_guard.as_ref() {
        Some(msd) => {
            if msd.state().await.connected {
                let body = RedfishError::general_error("Virtual media already inserted");
                return (StatusCode::CONFLICT, Json(body)).into_response();
            }

            info!("Redfish: VirtualMedia.InsertMedia requested");
            StatusCode::NO_CONTENT.into_response()
        }
        None => {
            let body = RedfishError::service_unavailable("MSD not available");
            (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
        }
    }
}

async fn virtual_media_eject(
    State(state): State<Arc<AppState>>,
    Path((manager_id, media_id)): Path<(String, String)>,
) -> Response {
    if manager_id != MANAGER_ID || media_id != VIRTUAL_MEDIA_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    let msd_guard = state.msd.read().await;
    match msd_guard.as_ref() {
        Some(msd) => {
            if !msd.state().await.connected {
                let body = RedfishError::general_error("No virtual media inserted");
                return (StatusCode::CONFLICT, Json(body)).into_response();
            }

            match msd.disconnect().await {
                Ok(()) => {
                    info!("Redfish: VirtualMedia.EjectMedia executed");
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(e) => {
                    warn!("Redfish: VirtualMedia.EjectMedia failed: {}", e);
                    let body = RedfishError::general_error(&e.to_string());
                    (StatusCode::BAD_REQUEST, Json(body)).into_response()
                }
            }
        }
        None => {
            let body = RedfishError::service_unavailable("MSD not available");
            (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
        }
    }
}

async fn session_service() -> Json<SessionService> {
    Json(SessionService {
        odata_type: "#SessionService.v1_1_8.SessionService".to_string(),
        odata_id: "/redfish/v1/SessionService".to_string(),
        odata_context: "/redfish/v1/$metadata#SessionService.SessionService".to_string(),
        Id: "SessionService".to_string(),
        Name: "Session Service".to_string(),
        Description: "Session Service".to_string(),
        ServiceEnabled: true,
        SessionTimeout: "PT24H".to_string(),
        Sessions: odata_ref("/redfish/v1/SessionService/Sessions"),
    })
}

async fn session_list(State(state): State<Arc<AppState>>) -> Json<Collection<ODataLink>> {
    let session_ids = state.sessions.list_ids().await.unwrap_or_default();
    let members: Vec<ODataLink> = session_ids
        .iter()
        .map(|id| odata_ref(&format!("/redfish/v1/SessionService/Sessions/{}", id)))
        .collect();
    let count = members.len() as u64;

    Json(Collection {
        odata_type: "#SessionCollection.SessionCollection".to_string(),
        odata_id: "/redfish/v1/SessionService/Sessions".to_string(),
        odata_context: "/redfish/v1/$metadata#SessionCollection.SessionCollection".to_string(),
        Name: "Session Collection".to_string(),
        Description: "Collection of Sessions".to_string(),
        members_count: count,
        Members: members,
    })
}

async fn session_create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SessionCreateRequest>,
) -> Response {
    let user = match state.users.verify(&req.UserName, &req.Password).await {
        Ok(Some(user)) => user,
        _ => {
            let body = RedfishError::invalid_credentials();
            return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
        }
    };

    let session = match state.sessions.create(&user.id).await {
        Ok(s) => s,
        Err(e) => {
            let body = RedfishError::general_error(&e.to_string());
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response();
        }
    };

    info!("Redfish: Session created for user '{}'", user.username);

    let session_location = format!(
        "/redfish/v1/SessionService/Sessions/{}",
        session.id
    );

    let body = Session {
        odata_type: "#Session.v1_0_0.Session".to_string(),
        odata_id: session_location.clone(),
        odata_context: "/redfish/v1/$metadata#Session.Session".to_string(),
        Id: session.id.clone(),
        Name: format!("Session for {}", user.username),
        Description: "Manager User Session".to_string(),
        UserName: user.username.clone(),
    };

    (
        StatusCode::CREATED,
        [
            ("X-Auth-Token", session.id),
            ("Location", session_location),
        ],
        Json(body),
    )
        .into_response()
}

async fn session_delete(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Response {
    match state.sessions.delete(&session_id).await {
        Ok(()) => {
            info!("Redfish: Session {} deleted", session_id);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            let body = RedfishError::general_error(&e.to_string());
            (StatusCode::NOT_FOUND, Json(body)).into_response()
        }
    }
}

async fn account_service() -> Json<AccountService> {
    Json(AccountService {
        odata_type: "#AccountService.v1_13_0.AccountService".to_string(),
        odata_id: "/redfish/v1/AccountService".to_string(),
        odata_context: "/redfish/v1/$metadata#AccountService.AccountService".to_string(),
        Id: "AccountService".to_string(),
        Name: "Account Service".to_string(),
        Description: "Account Service".to_string(),
        ServiceEnabled: true,
        Accounts: odata_ref("/redfish/v1/AccountService/Accounts"),
        Roles: odata_ref("/redfish/v1/AccountService/Roles"),
    })
}

async fn account_list(State(state): State<Arc<AppState>>) -> Response {
    let users = match state.users.list().await {
        Ok(u) => u,
        Err(e) => {
            let body = RedfishError::general_error(&e.to_string());
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response();
        }
    };

    let members: Vec<ODataLink> = users
        .iter()
        .map(|u| odata_ref(&format!("/redfish/v1/AccountService/Accounts/{}", u.id)))
        .collect();
    let count = members.len() as u64;

    let collection = Collection {
        odata_type: "#ManagerAccountCollection.ManagerAccountCollection".to_string(),
        odata_id: "/redfish/v1/AccountService/Accounts".to_string(),
        odata_context: "/redfish/v1/$metadata#ManagerAccountCollection.ManagerAccountCollection"
            .to_string(),
        Name: "Accounts Collection".to_string(),
        Description: "Collection of Accounts".to_string(),
        members_count: count,
        Members: members,
    };

    Json(collection).into_response()
}

async fn account_detail(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
) -> Response {
    let user = match state.users.get(&account_id).await {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(RedfishError::resource_not_found()),
            )
                .into_response();
        }
    };

    let account = ManagerAccount {
        odata_type: "#ManagerAccount.v1_12_0.ManagerAccount".to_string(),
        odata_id: format!("/redfish/v1/AccountService/Accounts/{}", user.id),
        odata_context: "/redfish/v1/$metadata#ManagerAccount.ManagerAccount".to_string(),
        Id: user.id.clone(),
        Name: format!("Account {}", user.username),
        Description: "User Account".to_string(),
        Enabled: true,
        UserName: user.username.clone(),
        RoleId: "Administrator".to_string(),
        Locked: false,
        Links: ManagerAccountLinks {
            Role: odata_ref("/redfish/v1/AccountService/Roles/Administrator"),
        },
    };

    Json(account).into_response()
}

async fn event_service() -> Json<EventService> {
    Json(EventService {
        odata_type: "#EventService.v1_8_1.EventService".to_string(),
        odata_id: "/redfish/v1/EventService".to_string(),
        odata_context: "/redfish/v1/$metadata#EventService.EventService".to_string(),
        Id: "EventService".to_string(),
        Name: "Event Service".to_string(),
        Description: "Event Service".to_string(),
        ServiceEnabled: true,
        DeliveryRetryAttempts: 3,
        DeliveryRetryIntervalSeconds: 30,
        EventFormatTypes: vec!["Event".to_string(), "MetricReport".to_string()],
        RegistryPrefixes: vec!["Base".to_string()],
        SubordinateResources: true,
        SSEFilterPropertiesSupported: SseFilterPropertiesSupported {
            EventFormatType: false,
            MessageId: false,
            MetricReportDefinition: false,
            OriginResource: false,
            RegistryPrefix: false,
            ResourceType: false,
        },
        Subscriptions: odata_ref("/redfish/v1/EventService/Subscriptions"),
        Actions: EventServiceActions {
            submit_test_event: ActionTarget {
                target: "/redfish/v1/EventService/Actions/EventService.SubmitTestEvent"
                    .to_string(),
            },
        },
    })
}

async fn event_service_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>>> {
    let mut device_info_rx = state.subscribe_device_info();

    let stream = async_stream::stream! {
        loop {
            match device_info_rx.changed().await {
                Ok(()) => {
                    let payload = json!({
                        "@odata.type": "#Event.v1_7_0.Event",
                        "Id": uuid::Uuid::new_v4().to_string(),
                        "Name": "One-KVM Event",
                        "Context": "One-KVM",
                        "Events": [
                            {
                                "EventType": "ResourceUpdated",
                                "EventId": uuid::Uuid::new_v4().to_string(),
                                "Severity": "OK",
                                "Message": "Device state updated",
                                "MessageId": "ResourceUpdated.1.0.0.ResourceUpdated"
                            }
                        ]
                    });

                    let event = Event::default().data(serde_json::to_string(&payload).unwrap_or_default());
                    yield Ok(event);
                }
                Err(_) => break,
            }
        }
    };

    Sse::new(Box::pin(stream)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text(":\n"),
    )
}

async fn system_patch(
    Path(system_id): Path<String>,
    Json(req): Json<ComputerSystemPatchRequest>,
) -> Response {
    if system_id != SYSTEM_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    if let Some(boot) = &req.Boot {
        if let Some(target) = &boot.BootSourceOverrideTarget {
            info!(
                "Redfish: PATCH Systems/{} BootSourceOverrideTarget='{}' (accepted, no-op — One-KVM cannot control BIOS)",
                system_id, target
            );
        }
    }

    let system = ComputerSystem {
        odata_type: "#ComputerSystem.v1_20_0.ComputerSystem".to_string(),
        odata_id: format!("/redfish/v1/Systems/{}", system_id),
        odata_context: "/redfish/v1/$metadata#ComputerSystem.ComputerSystem".to_string(),
        odata_etag: format!("W/\"{}\"", uuid::Uuid::new_v4()),
        Id: system_id.clone(),
        Name: "Managed System".to_string(),
        Description: "The managed computer system connected via One-KVM".to_string(),
        SystemType: "Physical".to_string(),
        AssetTag: String::new(),
        Manufacturer: "Unknown".to_string(),
        Model: "Unknown".to_string(),
        SerialNumber: String::new(),
        PartNumber: String::new(),
        PowerState: "On".to_string(),
        BiosVersion: "Unknown".to_string(),
        Status: Status::enabled_ok(),
        Boot: Boot {
            BootSourceOverrideEnabled: req
                .Boot
                .as_ref()
                .and_then(|b| b.BootSourceOverrideEnabled.clone())
                .unwrap_or_else(|| "Disabled".to_string()),
            BootSourceOverrideMode: req
                .Boot
                .as_ref()
                .and_then(|b| b.BootSourceOverrideMode.clone()),
            BootSourceOverrideTarget: req
                .Boot
                .as_ref()
                .and_then(|b| b.BootSourceOverrideTarget.clone()),
            UefiTargetBootSourceOverride: req
                .Boot
                .as_ref()
                .and_then(|b| b.UefiTargetBootSourceOverride.clone()),
        },
        ProcessorSummary: ProcessorSummary {
            Count: None,
            LogicalProcessorCount: None,
            Model: "Unknown".to_string(),
            Status: Status::enabled_ok(),
        },
        MemorySummary: MemorySummary {
            TotalSystemMemoryGiB: None,
            Status: Status::enabled_ok(),
        },
        TrustedModules: vec![],
        Actions: ComputerSystemActions {
            reset: ActionTarget {
                target: format!(
                    "/redfish/v1/Systems/{}/Actions/ComputerSystem.Reset",
                    system_id
                ),
            },
            set_default_boot_order: ActionTarget {
                target: format!(
                    "/redfish/v1/Systems/{}/Actions/ComputerSystem.SetDefaultBootOrder",
                    system_id
                ),
            },
        },
        Links: ComputerSystemLinks {
            Chassis: vec![odata_ref("/redfish/v1/Chassis/1")],
            ManagedBy: vec![odata_ref("/redfish/v1/Managers/1")],
        },
    };

    Json(system).into_response()
}

async fn event_submit_test() -> StatusCode {
    info!("Redfish: SubmitTestEvent received (no-op)");
    StatusCode::NO_CONTENT
}

async fn event_subscriptions_stub() -> Json<serde_json::Value> {
    Json(json!({
        "@odata.type": "#EventDestinationCollection.EventDestinationCollection",
        "@odata.id": "/redfish/v1/EventService/Subscriptions",
        "@odata.context": "/redfish/v1/$metadata#EventDestinationCollection.EventDestinationCollection",
        "Name": "Event Subscriptions Collection",
        "Description": "Collection of Event Subscriptions",
        "Members@odata.count": 0,
        "Members": []
    }))
}

async fn thermal_stub(Path(chassis_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "@odata.type": "#Thermal.v1_7_3.Thermal",
        "@odata.id": format!("/redfish/v1/Chassis/{}/Thermal", chassis_id),
        "@odata.context": "/redfish/v1/$metadata#Thermal.Thermal",
        "Id": "Thermal",
        "Name": "Thermal",
        "Description": "Thermal metrics (stub — not available on One-KVM)",
        "Temperatures": [],
        "Fans": [],
        "Status": { "State": "Disabled", "Health": "OK" }
    }))
}

async fn network_protocol_stub(Path(manager_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "@odata.type": "#ManagerNetworkProtocol.v1_10_0.ManagerNetworkProtocol",
        "@odata.id": format!("/redfish/v1/Managers/{}/NetworkProtocol", manager_id),
        "@odata.context": "/redfish/v1/$metadata#ManagerNetworkProtocol.ManagerNetworkProtocol",
        "Id": "NetworkProtocol",
        "Name": "Manager Network Protocol",
        "Description": "Network protocol settings (stub)",
        "Status": { "State": "Enabled", "Health": "OK" },
        "HTTP": { "ProtocolEnabled": true, "Port": 8080 },
        "HTTPS": { "ProtocolEnabled": false, "Port": 8443 },
        "SSDP": { "ProtocolEnabled": false }
    }))
}

async fn ethernet_interfaces_stub(Path(manager_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
        "@odata.id": format!("/redfish/v1/Managers/{}/EthernetInterfaces", manager_id),
        "@odata.context": "/redfish/v1/$metadata#EthernetInterfaceCollection.EthernetInterfaceCollection",
        "Name": "Ethernet Interface Collection",
        "Description": "Collection of Ethernet Interfaces",
        "Members@odata.count": 0,
        "Members": []
    }))
}

async fn log_services_stub(Path(manager_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "@odata.type": "#LogServiceCollection.LogServiceCollection",
        "@odata.id": format!("/redfish/v1/Managers/{}/LogServices", manager_id),
        "@odata.context": "/redfish/v1/$metadata#LogServiceCollection.LogServiceCollection",
        "Name": "Log Service Collection",
        "Description": "Collection of Log Services",
        "Members@odata.count": 0,
        "Members": []
    }))
}

async fn roles_stub() -> Json<serde_json::Value> {
    Json(json!({
        "@odata.type": "#RoleCollection.RoleCollection",
        "@odata.id": "/redfish/v1/AccountService/Roles",
        "@odata.context": "/redfish/v1/$metadata#RoleCollection.RoleCollection",
        "Name": "Roles Collection",
        "Description": "Collection of Roles",
        "Members@odata.count": 1,
        "Members": [
            { "@odata.id": "/redfish/v1/AccountService/Roles/Administrator" }
        ]
    }))
}

async fn role_detail_stub(Path(role_id): Path<String>) -> Response {
    if role_id != "Administrator" {
        return (
            StatusCode::NOT_FOUND,
            Json(RedfishError::resource_not_found()),
        )
            .into_response();
    }

    Json(json!({
        "@odata.type": "#Role.v1_3_1.Role",
        "@odata.id": "/redfish/v1/AccountService/Roles/Administrator",
        "@odata.context": "/redfish/v1/$metadata#Role.Role",
        "Id": "Administrator",
        "Name": "Administrator Role",
        "Description": "Administrator role with full access",
        "IsPredefined": true,
        "AssignedPrivileges": ["Login", "ConfigureManager", "ConfigureUsers", "ConfigureSelf", "ConfigureComponents"],
        "OemPrivileges": []
    }))
    .into_response()
}
