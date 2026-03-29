#![no_main]
//! Fuzz target for FleetManifest::from_yaml().
//!
//! Feeds arbitrary bytes into the fleet manifest parser to find panics,
//! stack overflows, or excessive resource consumption in YAML parsing
//! and validation logic.

use libfuzzer_sys::fuzz_target;
use ocean::fleet::manifest::FleetManifest;

fuzz_target!(|data: &[u8]| {
    // Set dummy env vars so credential resolution doesn't fail on otherwise-valid manifests.
    // This lets the fuzzer explore deeper code paths past env var resolution.
    std::env::set_var("GITHUB_TOKEN", "fuzz_tok");
    std::env::set_var("GITHUB_ORG", "fuzz_org");
    std::env::set_var("GITHUB_API_URL", "https://fuzz.example.com");
    std::env::set_var("OKTA_API_TOKEN", "fuzz_tok");
    std::env::set_var("OKTA_DOMAIN", "fuzz.okta.com");
    std::env::set_var("OKTA_ORG_URL", "https://fuzz.okta.com");
    std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAFUZZ");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "fuzz_secret");
    std::env::set_var("AWS_SESSION_TOKEN", "fuzz_session");
    std::env::set_var("AWS_REGION", "us-east-1");
    std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");
    std::env::set_var("AZURE_CLIENT_ID", "fuzz_client");
    std::env::set_var("AZURE_CLIENT_SECRET", "fuzz_secret");
    std::env::set_var("AZURE_TENANT_ID", "fuzz_tenant");
    std::env::set_var("AZURE_SUBSCRIPTION_ID", "fuzz_sub");

    // We only care about panics/hangs — errors are expected for most inputs.
    let _ = FleetManifest::from_yaml(data);
});
