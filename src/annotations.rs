use crate::constants::{self, AnnotationType, HashType, LayerType, LAYER_HOST};
use chrono::Local;
use serde::{Deserialize, Serialize};

fn default_host() -> LayerType {
    LAYER_HOST.clone()
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub key: String,
    pub hash: HashType,
    pub host: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default = "default_host")]
    pub layer: LayerType,
    pub kind: AnnotationType,
    pub signature: String,
    #[serde(rename = "isSatisfied")]
    pub is_satisfied: bool,
    pub timestamp: String,
}

#[derive(Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AnnotationList {
    pub items: Vec<Annotation>,
}

impl Annotation {
    pub fn new(
        key: &str,
        hash: HashType,
        host: &str,
        layer: LayerType,
        kind: AnnotationType,
        is_satisfied: bool,
        timestamp: Option<chrono::DateTime<Local>>,
    ) -> Self {
        Annotation {
            id: ulid::Ulid::new().to_string(),
            key: key.to_string(),
            hash,
            host: host.to_string(),
            tag: None,
            layer,
            kind,
            signature: String::new(),
            is_satisfied,
            timestamp: timestamp
                .unwrap_or_else(|| chrono::Local::now())
                .to_rfc3339(),
        }
    }

    pub fn set_tag(&mut self, tag: String) {
        self.tag = Some(tag);
    }

    pub fn with_signature(&mut self, signature: &str) {
        self.signature = signature.to_string()
    }

    pub fn validate_base(&self) -> bool {
        self.hash.is_base_hash_type() && self.kind.is_base_annotation_type()
    }
}

pub fn mock_annotation() -> Annotation {
    let key = "The hash of the contents";
    let hash = constants::SHA256_HASH.clone();
    let host = "Host Device";
    let layer = constants::LAYER_HOST.clone();
    let kind = constants::ANNOTATION_SOURCE.clone();
    let satisfied = true;
    let timestamp = None;

    Annotation::new(key, hash, host, layer, kind, satisfied, timestamp)
}
