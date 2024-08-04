use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

mod features;
use features::validate_admin_request::validate_admin_request as admin_request;

#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

#[wasm_bindgen]
pub fn validate_admin_request(request: JsValue, origins: JsValue, keys: JsValue) -> JsValue {
    let request = from_value(request).expect("Failed to deserialize request");
    let origins = from_value(origins).expect("Failed to deserialize origins");
    let keys = from_value(keys).expect("Failed to deserialize keys");

    let result = admin_request(&request, &origins, &keys);

    // Convert the result back to JsValue
    match result {
        Ok(payload) => to_value(&payload).expect("Failed to serialize payload"),
        Err(error_response) => {
            to_value(&error_response).expect("Failed to serialize error response")
        }
    }
}
