use crate::common::crypto::hash_password;
use crate::common::templates::{CNPasswordResetTemplate, ENPasswordResetTemplate};
use crate::config::state::AppState;
use crate::entity::users;
use crate::errors::app_error::AppError;
use crate::schemas::password::{ForgotPasswordDto, ResetPasswordDto};
use crate::{bad_request, not_found};
use askama::Template;
use sea_orm::{ActiveModelTrait, ColumnTrait, Condition, EntityTrait, QueryFilter, Set};
use url::Url;

#[derive(Clone)]
pub struct PasswordService {
    app_state: AppState,
}

impl PasswordService {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }

    pub async fn forgot_password(
        &self,
        referer_url: String,
        dto: ForgotPasswordDto,
    ) -> Result<(), AppError> {
        let mut user: users::ActiveModel = users::Entity::find()
            .filter(
                Condition::all()
                    .add(users::Column::Email.eq(&dto.email))
                    .add(users::Column::IsActive.eq(true)),
            )
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or(not_found!("No user with this email"))?
            .into();

        let reset_token = uuid::Uuid::new_v4().to_string();

        user.reset_token = Set(Some(reset_token.clone()));
        user.reset_triggered = Set(Some(chrono::Utc::now().naive_utc()));

        user.save(self.app_state.db.as_ref()).await?;

        let base_url = match Url::parse(referer_url.as_str()) {
            Ok(base_url) => base_url,
            Err(_) => return Err(bad_request!("Bad Request".to_string())),
        };

        let reset_url = match base_url.join(format!("/reset-password/{}", reset_token).as_str()) {
            Ok(reset_url) => reset_url,
            Err(_) => return Err(bad_request!("Bad Request".to_string())),
        };

        let (subject, rendered_html) = match dto.language.to_uppercase().as_str() {
            "CN" => {
                let subject = "[Axum Vue Admin] 密码重置请求";
                let template = CNPasswordResetTemplate {
                    reset_url: reset_url.as_str(),
                };
                (subject, template.render()?)
            }
            "EN" => {
                let subject = "[Axum Vue Admin] Password Reset Request";
                let template = ENPasswordResetTemplate {
                    reset_url: reset_url.as_str(),
                };
                (subject, template.render()?)
            }
            _ => {
                let subject = "[Axum Vue Admin] Password Reset Request";
                let template = ENPasswordResetTemplate {
                    reset_url: reset_url.as_str(),
                };
                (subject, template.render()?)
            }
        };

        self.app_state
            .email_service
            .send(
                "no-reply@axum_vue_admin.com",
                dto.email.as_str(),
                subject,
                rendered_html.as_str(),
            )
            .await?;
        Ok(())
    }

    pub async fn resets_password(
        &self,
        reset_token: String,
        dto: ResetPasswordDto,
    ) -> Result<(), AppError> {
        let mut user: users::ActiveModel = users::Entity::find()
            .filter(users::Column::ResetToken.eq(reset_token))
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or(not_found!("RestToken Not Found"))?
            .into();

        user.reset_token = Set(None);

        user.password = Set(hash_password(dto.new_password.as_str())?);

        user.save(self.app_state.db.as_ref()).await?;

        Ok(())
    }
}
