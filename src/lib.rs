use axum::{
    extract::{FromRef},
};
use sqlx::postgres::{PgPool};

pub mod certificates;
pub mod config;
pub mod extractors;
pub mod handlers;
pub mod models;


#[derive(FromRef, Clone)]
pub struct AppState {
    pub pool: PgPool,
}