use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

#[derive(Serialize, utoipa::ToSchema)]
pub struct DataResponse<T: Serialize> {
    pub data: T,
}

pub fn data<T: Serialize>(value: T) -> impl IntoResponse {
    Json(DataResponse { data: value })
}
