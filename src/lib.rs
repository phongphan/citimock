use axum::extract::FromRef;
use sqlx::postgres::PgPool;

pub mod certificates;
pub mod config;
pub mod extractors;
pub mod handlers;
pub mod models;
pub mod services;

#[derive(FromRef, Clone)]
pub struct AppState {
    pub pool: PgPool,
}

pub mod xmlsec {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(clippy::all)]

    include!(concat!(env!("OUT_DIR"), "/xmlsec_bindings.rs"));
}
