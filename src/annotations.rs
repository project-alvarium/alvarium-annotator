use crate::constants::{self, AnnotationType, HashType, LayerType};
use serde::{Deserialize, Serialize};

/// TAG_ENV_KEY is an environment key used to associate annotations with specific metadata,
/// aiding in the linkage of scores across different layers of the stack. For instance, in the "app" layer,
/// it is utilized to retrieve the commit SHA of the workload where the application is running,
/// which is instrumental in tracing the impact on the current layer's score from the lower layers.
pub static TAG_ENV_KEY: &'static str = "TAG";

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub key: String,
    pub hash: HashType,
    pub host: String,
    pub tag: String,
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
    ) -> Self {
        let timestamp = chrono::Local::now().to_rfc3339();
        Annotation {
            id: ulid::Ulid::new().to_string(),
            key: key.to_string(),
            hash,
            host: host.to_string(),
            tag: get_tag_value(&layer),
            layer,
            kind,
            signature: String::new(),
            is_satisfied,
            timestamp,
        }
    }

    pub fn with_signature(&mut self, signature: &str) {
        self.signature = signature.to_string()
    }

    pub fn validate_base(&self) -> bool {
        self.hash.is_base_hash_type() && self.kind.is_base_annotation_type()
    }
}

fn get_tag_value(layer: &LayerType) -> String {
    if layer.eq(&constants::LAYER_APP) {
        std::env::var(TAG_ENV_KEY).unwrap_or_default()
    } else {
        "".to_owned()
    }
}

pub fn mock_annotation() -> Annotation {
    let key = "The hash of the contents";
    let hash = constants::SHA256_HASH.clone();
    let host = "Host Device";
    let layer = constants::LAYER_HOST.clone();
    let kind = constants::ANNOTATION_SOURCE.clone();
    let satisfied = true;

    Annotation::new(key, hash, host, layer, kind, satisfied)
}
