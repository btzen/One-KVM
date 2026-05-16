use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use tracing::info;

use std::sync::Arc;

use super::super::schema::*;
use super::{empty_collection, resource_not_found};
use crate::auth::{Session, Privilege, UserRole};
use crate::state::AppState;

pub(crate) fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/AccountService", get(account_service))
        .route(
            "/v1/AccountService/Accounts",
            get(account_list).post(account_create),
        )
        .route(
            "/v1/AccountService/Accounts/{account_id}",
            get(account_detail)
                .patch(account_update)
                .delete(account_delete),
        )
        .route(
            "/v1/AccountService/Roles",
            get(roles_list),
        )
        .route(
            "/v1/AccountService/Roles/{role_id}",
            get(role_detail),
        )
        .with_state(state)
}

async fn account_service() -> Json<AccountService> {
    Json(AccountService {
        odata_type: "#AccountService.v1_13_0.AccountService".to_string(),
        odata_id: "/redfish/v1/AccountService".to_string(),
        odata_context: "/redfish/v1/$metadata#AccountService.AccountService".to_string(),
        id: "AccountService".to_string(),
        name: "Account Service".to_string(),
        description: "Account Service".to_string(),
        service_enabled: true,
        accounts: odata_ref("/redfish/v1/AccountService/Accounts"),
        roles: odata_ref("/redfish/v1/AccountService/Roles"),
    })
}

async fn account_list(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<Session>,
) -> Response {
    if !session.has_privilege(Privilege::Configure) {
        return (StatusCode::FORBIDDEN, Json(RedfishError::general_error("Insufficient privilege"))).into_response();
    }
    let users = match state.users.list_users().await {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response()
        }
    };

    let members: Vec<ODataLink> = users
        .iter()
        .map(|u| odata_ref(&format!("/redfish/v1/AccountService/Accounts/{}", u.id)))
        .collect();

    Json(empty_collection(
        "#ManagerAccountCollection.ManagerAccountCollection",
        "/redfish/v1/AccountService/Accounts",
        "/redfish/v1/$metadata#ManagerAccountCollection.ManagerAccountCollection",
        "Accounts Collection",
        "Collection of Accounts",
        members,
    ))
    .into_response()
}

async fn account_detail(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
    axum::Extension(session): axum::Extension<Session>,
) -> Response {
    if !session.has_privilege(Privilege::Configure) {
        return (StatusCode::FORBIDDEN, Json(RedfishError::general_error("Insufficient privilege"))).into_response();
    }
    let user = match state.users.get_by_id(&account_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return resource_not_found(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response()
        }
    };

    let role_id = user.role.as_str().to_string();

    Json(ManagerAccount {
        odata_type: "#ManagerAccount.v1_12_0.ManagerAccount".to_string(),
        odata_id: format!("/redfish/v1/AccountService/Accounts/{}", user.id),
        odata_context: "/redfish/v1/$metadata#ManagerAccount.ManagerAccount".to_string(),
        id: user.id,
        name: format!("Account {}", user.username),
        description: "User Account".to_string(),
        enabled: true,
        user_name: user.username,
        role_id: role_id.clone(),
        locked: false,
        links: ManagerAccountLinks {
            role: odata_ref(&format!("/redfish/v1/AccountService/Roles/{}", role_id)),
        },
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AccountCreateRequest {
    user_name: String,
    password: String,
    role_id: Option<String>,
}

async fn account_create(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<Session>,
    Json(req): Json<AccountCreateRequest>,
) -> Response {
    if !session.has_privilege(Privilege::Configure) {
        return (StatusCode::FORBIDDEN, axum::Json(RedfishError::general_error(
            "Insufficient privilege: Configure required",
        ))).into_response();
    }
    let role = match req.role_id.as_deref() {
        Some(r) => match UserRole::from_str(r) {
            Some(r) => r,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(RedfishError::general_error(&format!(
                        "Invalid RoleId '{}'. Valid: Administrator, Operator, Viewer",
                        r
                    ))),
                )
                    .into_response()
            }
        },
        None => UserRole::Operator,
    };

    let user = match state.users.create_user(&req.user_name, &req.password, role).await {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response()
        }
    };

    info!("Redfish: Account '{}' created with role {}", user.username, user.role);

    let role_id = user.role.as_str().to_string();
    let location = format!("/redfish/v1/AccountService/Accounts/{}", user.id);

    (
        StatusCode::CREATED,
        [("Location", location)],
        Json(ManagerAccount {
            odata_type: "#ManagerAccount.v1_12_0.ManagerAccount".to_string(),
            odata_id: format!("/redfish/v1/AccountService/Accounts/{}", user.id),
            odata_context: "/redfish/v1/$metadata#ManagerAccount.ManagerAccount".to_string(),
            id: user.id,
            name: format!("Account {}", user.username),
            description: "User Account".to_string(),
            enabled: true,
            user_name: user.username,
            role_id: role_id.clone(),
            locked: false,
            links: ManagerAccountLinks {
                role: odata_ref(&format!("/redfish/v1/AccountService/Roles/{}", role_id)),
            },
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AccountUpdateRequest {
    user_name: Option<String>,
    password: Option<String>,
    role_id: Option<String>,
}

async fn account_update(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<Session>,
    Path(account_id): Path<String>,
    Json(req): Json<AccountUpdateRequest>,
) -> Response {
    if !session.has_privilege(Privilege::Configure) {
        return (StatusCode::FORBIDDEN, axum::Json(RedfishError::general_error(
            "Insufficient privilege: Configure required",
        ))).into_response();
    }

    if let Some(ref role_str) = req.role_id {
        if account_id == session.user_id {
            let new_role = UserRole::from_str(role_str).unwrap_or(UserRole::Viewer);
            if new_role != UserRole::Administrator {
                return (StatusCode::BAD_REQUEST, axum::Json(RedfishError::general_error(
                    "Cannot remove your own Administrator role",
                ))).into_response();
            }
        }
    }
    if let Some(ref username) = req.user_name {
        if let Err(e) = state.users.update_username(&account_id, username).await {
            return (
                StatusCode::BAD_REQUEST,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response();
        }
    }

    if let Some(ref password) = req.password {
        if let Err(e) = state.users.update_password(&account_id, password).await {
            return (
                StatusCode::BAD_REQUEST,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response();
        }
    }

    if let Some(ref role_str) = req.role_id {
        let new_role = match UserRole::from_str(role_str) {
            Some(r) => r,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(RedfishError::general_error("Invalid RoleId")),
                )
                    .into_response()
            }
        };

        let target = match state.users.get_by_id(&account_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return resource_not_found(),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RedfishError::general_error(&e.to_string())),
                )
                    .into_response()
            }
        };

        if target.role == UserRole::Administrator && new_role != UserRole::Administrator {
            match state.users.role_count(UserRole::Administrator).await {
                Ok(count) if count <= 1 => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(RedfishError::general_error(
                            "Cannot remove the last Administrator",
                        )),
                    )
                        .into_response()
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(RedfishError::general_error(&e.to_string())),
                    )
                        .into_response()
                }
                _ => {}
            }
        }

        if let Err(e) = state.users.update_role(&account_id, new_role).await {
            return (
                StatusCode::BAD_REQUEST,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response();
        }
    }

    info!("Redfish: Account {} updated", account_id);

    account_detail(
        State(state),
        Path(account_id),
        axum::Extension(session),
    )
    .await
}

async fn account_delete(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<Session>,
    Path(account_id): Path<String>,
) -> Response {
    if !session.has_privilege(Privilege::Configure) {
        return (StatusCode::FORBIDDEN, axum::Json(RedfishError::general_error(
            "Insufficient privilege: Configure required",
        ))).into_response();
    }

    if account_id == session.user_id {
        return (StatusCode::BAD_REQUEST, axum::Json(RedfishError::general_error(
            "Cannot delete your own account",
        ))).into_response();
    }
    let target = match state.users.get_by_id(&account_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return resource_not_found(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response()
        }
    };

    if target.role == UserRole::Administrator {
        match state.users.role_count(UserRole::Administrator).await {
            Ok(count) if count <= 1 => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(RedfishError::general_error(
                        "Cannot delete the last Administrator",
                    )),
                )
                    .into_response()
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RedfishError::general_error(&e.to_string())),
                )
                    .into_response()
            }
            _ => {}
        }
    }

    let revoked = state.sessions.delete_by_user(&account_id).await.unwrap_or_default();
    state.remember_revoked_sessions(revoked).await;

    if let Err(e) = state.users.delete_user(&account_id).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RedfishError::general_error(&e.to_string())),
        )
            .into_response();
    }

    info!("Redfish: Account {} deleted", account_id);
    StatusCode::NO_CONTENT.into_response()
}

async fn roles_list() -> Json<serde_json::Value> {
    let roles: Vec<serde_json::Value> = UserRole::ALL
        .iter()
        .map(|r| {
            serde_json::json!({
                "@odata.id": format!("/redfish/v1/AccountService/Roles/{}", r.as_str())
            })
        })
        .collect();

    Json(serde_json::json!({
        "@odata.type": "#RoleCollection.RoleCollection",
        "@odata.id": "/redfish/v1/AccountService/Roles",
        "@odata.context": "/redfish/v1/$metadata#RoleCollection.RoleCollection",
        "Name": "Roles Collection",
        "Description": "Collection of Roles",
        "Members@odata.count": roles.len(),
        "Members": roles
    }))
}

async fn role_detail(Path(role_id): Path<String>) -> Response {
    let role = match UserRole::from_str(&role_id) {
        Some(r) => r,
        None => return resource_not_found(),
    };

    let privileges: Vec<String> = role
        .privileges()
        .iter()
        .map(|p| format!("{:?}", p))
        .collect();

    let description = match role {
        UserRole::Administrator => "Administrator role with full access to all system management functions",
        UserRole::Operator => "Operator role for console operations",
        UserRole::Viewer => "Viewer role for viewing system status and console stream",
    };

    Json(serde_json::json!({
        "@odata.type": "#Role.v1_3_1.Role",
        "@odata.id": format!("/redfish/v1/AccountService/Roles/{}", role.as_str()),
        "@odata.context": "/redfish/v1/$metadata#Role.Role",
        "Id": role.as_str(),
        "Name": format!("{} Role", role.display_name()),
        "Description": description,
        "IsPredefined": true,
        "AssignedPrivileges": privileges,
        "OemPrivileges": []
    }))
    .into_response()
}
