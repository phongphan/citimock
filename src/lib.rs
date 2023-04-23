use sqlx::postgres::PgPool;

pub mod certificates;
pub mod config;
pub mod extractors;
pub mod handlers;
pub mod models;
pub mod services;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_pri: String,
    pub jwt_pub: String,
}

#[derive(Clone)]
pub struct SessionState {
    pub client_id: String,
    pub auth_type: String,
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
