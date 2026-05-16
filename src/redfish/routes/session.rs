use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get},
    Json, Router,
};
use tracing::info;

use std::sync::Arc;

use super::super::schema::*;
use super::empty_collection;
use crate::auth::{Session as AuthSession, Privilege};
use crate::state::AppState;

pub(crate) fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/SessionService", get(session_service))
        .route(
            "/v1/SessionService/Sessions",
            get(session_list).post(session_create),
        )
        .route(
            "/v1/SessionService/Sessions/{session_id}",
            delete(session_delete),
        )
        .with_state(state)
}

async fn session_service() -> Json<SessionService> {
    Json(SessionService {
        odata_type: "#SessionService.v1_1_8.SessionService".to_string(),
        odata_id: "/redfish/v1/SessionService".to_string(),
        odata_context: "/redfish/v1/$metadata#SessionService.SessionService".to_string(),
        id: "SessionService".to_string(),
        name: "Session Service".to_string(),
        description: "Session Service".to_string(),
        service_enabled: true,
        session_timeout: "PT24H".to_string(),
        sessions: odata_ref("/redfish/v1/SessionService/Sessions"),
    })
}

async fn session_list(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<AuthSession>,
) -> Response {
    if !session.has_privilege(Privilege::Configure) {
        return (StatusCode::FORBIDDEN, Json(RedfishError::general_error("Insufficient privilege"))).into_response();
    }
    let session_ids = match state.sessions.list_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response()
        }
    };

    let mut members = Vec::new();
    for id in &session_ids {
        if state.sessions.get(id).await.ok().flatten().is_some() {
            members.push(odata_ref(&format!(
                "/redfish/v1/SessionService/Sessions/{}",
                id
            )));
        }
    }

    Json(empty_collection(
        "#SessionCollection.SessionCollection",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/$metadata#SessionCollection.SessionCollection",
        "Session Collection",
        "Collection of Sessions",
        members,
    ))
    .into_response()
}

async fn session_create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SessionCreateRequest>,
) -> Response {
    let user = match state.users.verify(&req.user_name, &req.password).await {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(RedfishError::invalid_credentials()),
            )
                .into_response()
        }
    };

    if !state.config.get().auth.single_user_allow_multiple_sessions {
        let revoked_ids = state
            .sessions
            .delete_by_user(&user.id)
            .await
            .unwrap_or_default();
        state.remember_revoked_sessions(revoked_ids).await;
    }

    let session = match state.sessions.create(&user.id, user.role).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response()
        }
    };

    let role_id = user.role.as_str().to_string();

    info!("Redfish: Session created for user '{}'", user.username);

    let location = format!("/redfish/v1/SessionService/Sessions/{}", session.id);

    (
        StatusCode::CREATED,
        [
            ("X-Auth-Token", session.id.clone()),
            ("Location", location.clone()),
        ],
        Json(Session {
            odata_type: "#Session.v1_0_0.Session".to_string(),
            odata_id: location,
            odata_context: "/redfish/v1/$metadata#Session.Session".to_string(),
            id: session.id,
            name: format!("Session for {}", user.username),
            description: "Manager User Session".to_string(),
            user_name: user.username,
            role_id,
        }),
    )
        .into_response()
}

async fn session_delete(
    State(state): State<Arc<AppState>>,
    axum::Extension(caller_session): axum::Extension<AuthSession>,
    Path(session_id): Path<String>,
) -> Response {
    let target_session = match state.sessions.get(&session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(RedfishError::resource_not_found()),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("Redfish: Session lookup failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RedfishError::general_error(&e.to_string())),
            )
                .into_response();
        }
    };

    let is_own = target_session.user_id == caller_session.user_id;
    let is_admin = caller_session.has_privilege(Privilege::Configure);

    if !is_own && !is_admin {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(RedfishError::general_error(
                "Can only delete your own sessions",
            )),
        )
            .into_response();
    }

    if let Err(e) = state.sessions.delete(&session_id).await {
        tracing::warn!("Redfish: Session delete failed: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RedfishError::general_error(&e.to_string())),
        )
            .into_response();
    }
    info!("Redfish: Session {} deleted", session_id);
    StatusCode::NO_CONTENT.into_response()
}
