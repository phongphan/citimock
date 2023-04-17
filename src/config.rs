use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use sqlx::PgPool;
use tokio::time::Duration;

pub async fn create_connection_pool(app_name: &str) -> PgPool {
    let db_connection_str = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:@127.0.0.1/citimock".to_string());
    let after_connect_statement = format!("SET application_name = '{}';", app_name);

    PgPoolOptions::new()
        .after_connect(move |conn, _meta| {
            let statement = after_connect_statement.clone();
            Box::pin(async move {
                conn.execute(&*statement).await?;

                Ok(())
            })
        })
        .max_connections(32)
        .acquire_timeout(Duration::from_secs(3))
        .idle_timeout(Duration::from_secs(180))
        .max_lifetime(Duration::from_secs(60 * 60 * 6)) // retired every 6 hours
        .connect(&db_connection_str)
        .await
        .expect("can't connect to database")
}
