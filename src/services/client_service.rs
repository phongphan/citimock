use sqlx::postgres::PgPool;

use crate::models::client::Client;

pub async fn get_client_by_id(conn: &PgPool, client_id: &str) -> Result<Client, sqlx::Error> {
    sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_one(conn)
        .await
}

pub async fn add_client(conn: &PgPool, client: &Client) -> Result<Client, sqlx::Error> {
    sqlx::query("INSERT INTO clients (client_id, name, status, hash, inserted_at, updated_at) values($1, $2, $3, $4, $5, $6);")
        .bind(client.client_id())
        .bind(client.name())
        .bind(client.status())
        .bind(client.hash())
        .bind(client.inserted_at())
        .bind(client.updated_at())
        .execute(conn)
        .await?;
    get_client_by_id(conn, client.client_id()).await
}
