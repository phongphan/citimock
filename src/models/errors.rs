#[derive(Debug, Serialize)]
struct CommonErrorResponse { // errormessage or errorResponse randomly (internal system inconsistency)
	http_code: String,		// httpCode
	http_message: String,	// httpMessage
	information: String,	// moreInformation
}