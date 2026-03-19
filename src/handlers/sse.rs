use crate::services::sse::SSEService;

use crate::errors::app_error::AppError;
use crate::schemas::auth::{AuthUser, Claims};
use axum::extract::State;
use axum::{
    response::sse::{Event, KeepAlive, Sse},
    Extension,
};
use futures_util::Stream;
use tokio_stream::StreamExt;

pub async fn global_message_push(
    State(service): State<SSEService>,
    Extension(current_user): Extension<Claims>,
) -> Sse<impl Stream<Item = Result<Event, AppError>>> {
    let stream = service
        .global_message(AuthUser::from(current_user))
        .await
        .map(|data| Ok(Event::default().data(data)));
    Sse::new(stream).keep_alive(KeepAlive::default())
}
