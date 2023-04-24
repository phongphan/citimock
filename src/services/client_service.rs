use crate::models::client::Client;
use sqlx::PgPool;

pub async fn get_client_by_uid(conn: &PgPool, uid: &str) -> Result<Client, sqlx::Error> {
    sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE uid = $1")
        .bind(uid)
        .fetch_one(conn)
        .await
}

pub async fn add_client(conn: &PgPool, client: &Client) -> Result<Client, sqlx::Error> {
    sqlx::query("INSERT INTO clients (uid, name, status, hash, inserted_at, updated_at) values($1, $2, $3, $4, $5, $6);")
        .bind(client.uid())
        .bind(client.name())
        .bind(client.status())
        .bind(client.hash())
        .bind(client.inserted_at())
        .bind(client.updated_at())
        .execute(conn)
        .await?;
    get_client_by_uid(conn, client.uid()).await
}
