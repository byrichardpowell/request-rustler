use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

mod features;
use features::validate_admin_request::{validate_admin_request as admin_request, LogFn};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn validate_admin_request(request: JsValue, config: JsValue) -> JsValue {
    let request = from_value(request).expect("Failed to deserialize request");
    let config = from_value(config).expect("Failed to deserialize config");
    let result = admin_request(&request, &config, log as LogFn);

    // Convert the result back to JsValue
    match result {
        Ok(payload) => to_value(&payload).expect("Failed to serialize payload"),
        Err(error_response) => {
            to_value(&error_response).expect("Failed to serialize error response")
        }
    }
}
