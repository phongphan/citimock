use sqlx::PgPool;

#[derive(Clone)]
pub struct CertManager {
    pool: PgPool,
}

impl CertManager {
    pub fn new(pool: PgPool) -> Self {
        CertManager { pool }
    }

    pub async fn find_dsig_cert(&self, client_id: &str) -> Option<String> {
        let result: Result<Option<String>, sqlx::Error> = sqlx::query_scalar(
            "SELECT cert FROM certificates
                WHERE client_id = $1
                    AND cert_type = $2
                    AND deleted_at IS NULL
                    AND NOW()::timestamp > valid_from
                    AND NOW()::timestamp < valid_to
                    ORDER BY valid_to ASC",
        )
        .bind(client_id)
        .bind("xml-dsig")
        .fetch_optional(&self.pool)
        .await;
        //println!("find_dsig_cert: {:?}", result);

        result.unwrap_or(None)
    }

    pub async fn find_enc_cert(&self, client_id: &str) -> Option<String> {
        let result: Result<Option<String>, sqlx::Error> = sqlx::query_scalar(
            "SELECT cert FROM certificates
                WHERE client_id = $1
                    AND cert_type = $2
                    AND deleted_at IS NULL
                    AND NOW()::timestamp > valid_from
                    AND NOW()::timestamp < valid_to
                    ORDER BY valid_to ASC",
        )
        .bind(client_id)
        .bind("xml-enc")
        .fetch_optional(&self.pool)
        .await;
        //println!("find_enc_cert: {:?}", result);

        result.unwrap_or(None)
    }
}