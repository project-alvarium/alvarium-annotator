use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::sync::LazyLock;

pub trait Validate {
    fn validate(&self) -> bool;
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Hash)]
pub struct HashType(pub String);
pub static NO_HASH: LazyLock<HashType> = LazyLock::new(|| HashType(String::from("none")));
pub static MD5_HASH: LazyLock<HashType> = LazyLock::new(|| HashType(String::from("md5")));
pub static SHA256_HASH: LazyLock<HashType> = LazyLock::new(|| HashType(String::from("sha256")));

impl HashType {
    pub fn is_base_hash_type(&self) -> bool {
        self == MD5_HASH.deref() || self == SHA256_HASH.deref() || self == NO_HASH.deref()
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Hash)]
pub struct KeyAlgorithm(pub String);
pub static ED25519_KEY: LazyLock<KeyAlgorithm> =
    LazyLock::new(|| KeyAlgorithm(String::from("ed25519")));
pub static CUSTOM_KEY: LazyLock<KeyAlgorithm> =
    LazyLock::new(|| KeyAlgorithm(String::from("custom")));

impl KeyAlgorithm {
    pub fn is_base_key_algorithm(&self) -> bool {
        self == ED25519_KEY.deref()
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Hash)]
pub struct StreamType(pub String);
pub static DEMIA_STREAM: LazyLock<StreamType> = LazyLock::new(|| StreamType(String::from("demia")));
pub static MOCK_STREAM: LazyLock<StreamType> = LazyLock::new(|| StreamType(String::from("mock")));
pub static MQTT_STREAM: LazyLock<StreamType> = LazyLock::new(|| StreamType(String::from("mqtt")));
pub static CUSTOM_STREAM: LazyLock<StreamType> =
    LazyLock::new(|| StreamType(String::from("custom")));

impl StreamType {
    pub fn is_base_stream_type(&self) -> bool {
        self == DEMIA_STREAM.deref() || self == MOCK_STREAM.deref() || self == MQTT_STREAM.deref()
    }
}
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Hash)]
pub struct AnnotationType(pub String);

pub static ANNOTATION_TPM: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("tpm")));
pub static ANNOTATION_MOCK: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("mock")));
pub static ANNOTATION_TLS: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("tls")));
pub static ANNOTATION_PKI: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("pki")));
pub static ANNOTATION_PKI_HTTP: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("pki-http")));
pub static ANNOTATION_SOURCE_CODE: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("source-code")));
pub static ANNOTATION_CHECKSUM: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("checksum")));
pub static ANNOTATION_VULNERABILITY: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("vulnerability")));
pub static ANNOTATION_SOURCE: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("src")));
pub static ANNOTATION_SBOM: LazyLock<AnnotationType> =
    LazyLock::new(|| AnnotationType(String::from("sbom")));

impl AnnotationType {
    pub fn kind(&self) -> &str {
        &self.0
    }
    pub fn is_base_annotation_type(&self) -> bool {
        self == ANNOTATION_TPM.deref()
            || self == ANNOTATION_MOCK.deref()
            || self == ANNOTATION_TLS.deref()
            || self == ANNOTATION_PKI.deref()
            || self == ANNOTATION_PKI_HTTP.deref()
            || self == ANNOTATION_SOURCE_CODE.deref()
            || self == ANNOTATION_CHECKSUM.deref()
            || self == ANNOTATION_VULNERABILITY.deref()
            || self == ANNOTATION_SOURCE.deref()
            || self == ANNOTATION_SBOM.deref()
    }
}

impl TryFrom<&str> for AnnotationType {
    type Error = Error;
    fn try_from(kind: &str) -> Result<Self> {
        match kind {
            "tpm" => Ok(ANNOTATION_TPM.clone()),
            "mock" => Ok(ANNOTATION_MOCK.clone()),
            "tls" => Ok(ANNOTATION_TLS.clone()),
            "pki" => Ok(ANNOTATION_PKI.clone()),
            "pki-http" => Ok(ANNOTATION_PKI_HTTP.clone()),
            "source-code" => Ok(ANNOTATION_SOURCE_CODE.clone()),
            "checksum" => Ok(ANNOTATION_CHECKSUM.clone()),
            "vulnerability" => Ok(ANNOTATION_VULNERABILITY.clone()),
            "src" => Ok(ANNOTATION_SOURCE.clone()),
            "sbom" => Ok(ANNOTATION_SBOM.clone()),
            _ => Err(Error::UnknownAnnotation(kind.to_string())),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Hash)]
pub struct LayerType(pub String);
pub static LAYER_APP: LazyLock<LayerType> = LazyLock::new(|| LayerType(String::from("app")));
pub static LAYER_CICD: LazyLock<LayerType> = LazyLock::new(|| LayerType(String::from("cicd")));
pub static LAYER_OS: LazyLock<LayerType> = LazyLock::new(|| LayerType(String::from("os")));
pub static LAYER_HOST: LazyLock<LayerType> = LazyLock::new(|| LayerType(String::from("host")));

impl LayerType {
    pub fn kind(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for LayerType {
    type Error = Error;
    fn try_from(kind: &str) -> Result<Self> {
        match kind {
            "app" => Ok(LAYER_APP.clone()),
            "cicd" => Ok(LAYER_CICD.clone()),
            "os" => Ok(LAYER_OS.clone()),
            "host" => Ok(LAYER_HOST.clone()),
            _ => Err(Error::UnknownLayer(kind.to_string())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SdkAction(pub String);
pub static ACTION_CREATE: LazyLock<SdkAction> = LazyLock::new(|| SdkAction(String::from("create")));
pub static ACTION_MUTATE: LazyLock<SdkAction> = LazyLock::new(|| SdkAction(String::from("mutate")));
pub static ACTION_TRANSIT: LazyLock<SdkAction> =
    LazyLock::new(|| SdkAction(String::from("transit")));
pub static ACTION_PUBLISH: LazyLock<SdkAction> =
    LazyLock::new(|| SdkAction(String::from("publish")));

impl SdkAction {
    pub fn is_base_action(&self) -> bool {
        self == ACTION_CREATE.deref()
            || self == ACTION_MUTATE.deref()
            || self == ACTION_TRANSIT.deref()
            || self == ACTION_PUBLISH.deref()
    }
}
