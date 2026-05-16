use axum::{extract::State, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

use crate::auth::{Session, User, UserRole};
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::web::handlers::LoginResponse;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    axum::Extension(_session): axum::Extension<Session>,
) -> Result<Json<Vec<User>>> {
    let users = state.users.list_users().await?;
    Ok(Json(users))
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    axum::Extension(_session): axum::Extension<Session>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<LoginResponse>> {
    let role = UserRole::from_str(req.role.as_deref().unwrap_or("Operator"))
        .ok_or_else(|| AppError::BadRequest(format!(
            "Invalid role '{}'. Valid roles: Administrator, Operator, Viewer",
            req.role.as_deref().unwrap_or("")
        )))?;

    let user = state.users.create_user(&req.username, &req.password, role).await?;
    info!("User '{}' created with role {}", user.username, user.role);

    Ok(Json(LoginResponse {
        success: true,
        message: Some("User created".to_string()),
    }))
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub role: Option<String>,
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<Session>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<LoginResponse>> {
    if let Some(ref username) = req.username {
        state.users.update_username(&user_id, username).await?;
    }

    if let Some(ref password) = req.password {
        if password.len() < 4 {
            return Err(AppError::BadRequest(
                "Password must be at least 4 characters".to_string(),
            ));
        }
        state.users.update_password(&user_id, password).await?;
    }

    if let Some(ref role_str) = req.role {
        let new_role = UserRole::from_str(role_str)
            .ok_or_else(|| AppError::BadRequest("Invalid role".to_string()))?;

        if user_id == session.user_id && new_role != UserRole::Administrator {
            return Err(AppError::BadRequest(
                "Cannot remove your own Administrator role".to_string(),
            ));
        }

        let target = state
            .users
            .get_by_id(&user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if target.role == UserRole::Administrator && new_role != UserRole::Administrator {
            let admin_count = state.users.role_count(UserRole::Administrator).await?;
            if admin_count <= 1 {
                return Err(AppError::BadRequest(
                    "Cannot remove the last Administrator".to_string(),
                ));
            }
        }

        state.users.update_role(&user_id, new_role).await?;
    }

    info!("User {} updated by {}", user_id, session.user_id);

    Ok(Json(LoginResponse {
        success: true,
        message: Some("User updated".to_string()),
    }))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<Session>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<LoginResponse>> {
    if user_id == session.user_id {
        return Err(AppError::BadRequest("Cannot delete yourself".to_string()));
    }

    let target = state
        .users
        .get_by_id(&user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if target.role == UserRole::Administrator {
        let admin_count = state.users.role_count(UserRole::Administrator).await?;
        if admin_count <= 1 {
            return Err(AppError::BadRequest(
                "Cannot remove the last Administrator".to_string(),
            ));
        }
    }

    let revoked = state.sessions.delete_by_user(&user_id).await?;
    state.remember_revoked_sessions(revoked).await;

    state.users.delete_user(&user_id).await?;
    info!("User {} deleted by {}", user_id, session.user_id);

    Ok(Json(LoginResponse {
        success: true,
        message: Some("User deleted".to_string()),
    }))
}
