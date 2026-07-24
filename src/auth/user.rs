use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use super::password::{hash_password, verify_password};
use crate::error::{AppError, Result};

type UserRow = (String, String, String, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum UserRole {
    Administrator,
    Operator,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Privilege {
    Operate,
    Configure,
}

impl UserRole {
    pub const ALL: [Self; 3] = [Self::Administrator, Self::Operator, Self::Viewer];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Administrator => "Administrator",
            Self::Operator => "Operator",
            Self::Viewer => "Viewer",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str().eq_ignore_ascii_case(s))
    }

    pub fn privileges(&self) -> &'static [Privilege] {
        match self {
            Self::Administrator => &[
                Privilege::Operate,
                Privilege::Configure,
            ],
            Self::Operator => &[
                Privilege::Operate,
            ],
            Self::Viewer => &[],
        }
    }

    pub fn has_privilege(&self, priv_: Privilege) -> bool {
        self.privileges().contains(&priv_)
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Administrator => "Administrator",
            Self::Operator => "Operator",
            Self::Viewer => "Viewer",
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Privilege {
    pub const ALL: [Self; 2] = [
        Self::Operate,
        Self::Configure,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Operate => "Operate",
            Self::Configure => "Configure",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: UserRole,
}

impl User {
    fn from_row(row: UserRow) -> Self {
        let (id, username, password_hash, role_str) = row;
        Self {
            id,
            username,
            password_hash,
            role: UserRole::from_str(&role_str).unwrap_or(UserRole::Viewer),
        }
    }

    pub fn has_privilege(&self, priv_: Privilege) -> bool {
        self.role.has_privilege(priv_)
    }
}

#[derive(Clone)]
pub struct UserStore {
    pool: Pool<Sqlite>,
}

impl UserStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    /// The first local user (by rowid), or `None` if none exists.
    /// Used by CLI admin tools; web API should use `get_by_id` or `list_users`.
    pub async fn single_user(&self) -> Result<Option<User>> {
        let rows: Vec<UserRow> = sqlx::query_as(
            "SELECT id, username, password_hash, role FROM users ORDER BY rowid ASC LIMIT 1",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().next().map(User::from_row))
    }

    pub async fn get_by_id(&self, user_id: &str) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, username, password_hash, role FROM users WHERE id = ?1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(User::from_row))
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows: Vec<UserRow> = sqlx::query_as(
            "SELECT id, username, password_hash, role FROM users ORDER BY rowid ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(User::from_row).collect())
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: UserRole,
    ) -> Result<User> {
        if username.len() < 2 {
            return Err(AppError::BadRequest(
                "Username must be at least 2 characters".to_string(),
            ));
        }
        if password.len() < 4 {
            return Err(AppError::BadRequest(
                "Password must be at least 4 characters".to_string(),
            ));
        }

        let password_hash = hash_password(password)?;
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            password_hash,
            role,
        };

        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, role)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .execute(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn create_first_user(&self, username: &str, password: &str) -> Result<User> {
        self.create_user(username, password, UserRole::Administrator).await
    }

    pub async fn verify(&self, username: &str, password: &str) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        let user = match row {
            Some(u) => User::from_row(u),
            None => return Ok(None),
        };

        if verify_password(password, &user.password_hash)? {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn update_password(&self, user_id: &str, new_password: &str) -> Result<()> {
        let password_hash = hash_password(new_password)?;
        let now = OffsetDateTime::now_utc();

        let result =
            sqlx::query("UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3")
                .bind(&password_hash)
                .bind(now.format(&Rfc3339).expect("RFC3339 format"))
                .bind(user_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        Ok(())
    }

    pub async fn update_username(&self, user_id: &str, new_username: &str) -> Result<()> {
        if new_username.len() < 2 {
            return Err(AppError::BadRequest(
                "Username must be at least 2 characters".to_string(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        let result = sqlx::query("UPDATE users SET username = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(new_username)
            .bind(now.format(&Rfc3339).expect("RFC3339 format"))
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        Ok(())
    }

    pub async fn update_role(&self, user_id: &str, new_role: UserRole) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let result = sqlx::query("UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(new_role.as_str())
            .bind(now.format(&Rfc3339).expect("RFC3339 format"))
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        Ok(())
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        Ok(())
    }

    pub async fn role_count(&self, role: UserRole) -> Result<i64> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = ?1")
                .bind(role.as_str())
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }
}
