use crate::services::cert_manager_service::CertManager;
use sqlx::postgres::PgPool;

pub mod certificates;
pub mod config;
pub mod extractors;
pub mod handlers;
pub mod layers;
pub mod models;
pub mod services;

#[derive(Clone)]
pub struct AppState {
    pub cert_manager: CertManager,
    pub pool: PgPool,
    pub jwt_pri: String,
    pub jwt_pub: String,
    pub default_dsig_cert: String,
    pub default_enc_cert: String,
}

#[derive(Clone)]
pub struct SessionState {
    pub client_id: String,
    pub auth_type: String,
    pub authenticated: bool,
    pub dsig_cert: String,
    pub enc_cert: String,
}

pub mod xmlsec {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(clippy::all)]

    include!(concat!(env!("OUT_DIR"), "/xmlsec_bindings.rs"));
}
