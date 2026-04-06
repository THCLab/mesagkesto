use messagebox::openapi::ApiDoc;
use utoipa::OpenApi;

#[test]
fn export_openapi_spec() {
    let spec = ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&spec).expect("Failed to serialize OpenAPI spec to YAML");

    let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("openapi.yaml");
    std::fs::write(&spec_path, &yaml).expect("Failed to write openapi.yaml");
}
