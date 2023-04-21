use yaserde_derive::YaSerialize;

// errormessage or errorResponse randomly (internal system inconsistency)

#[derive(Debug, YaSerialize)]
#[yaserde(rename = "errormessage")]
pub struct CommonErrorResponse {
    #[yaserde(rename = "httpCode")]
    pub http_code: String,

    #[yaserde(rename = "httpMessage")]
    pub http_message: String,

    #[yaserde(rename = "moreInformation")]
    pub information: String,
}

#[derive(Debug, YaSerialize)]
#[yaserde(rename = "errorResponse")]
pub struct AnotherCommonErrorResponse {
    #[yaserde(rename = "httpCode")]
    pub http_code: String,

    #[yaserde(rename = "httpMessage")]
    pub http_message: String,

    #[yaserde(rename = "moreInformation")]
    pub information: String,
}
