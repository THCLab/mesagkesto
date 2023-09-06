use crate::{GenericEvent, Version};
use said::{derivation::HashFunction, sad::SerializationFormats};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
enum QueryType {
    Qry,
}

#[derive(Deserialize, Serialize)]
pub struct QueryMessage<V: Version + Serialize + Clone, D: Serialize + Clone>(
    GenericEvent<V, QueryType, D>,
);

impl<V: Version + Serialize + Clone, D: Serialize + Clone> QueryMessage<V, D> {
    pub fn new(format: SerializationFormats, derivation: HashFunction, route: D) -> Self {
        let ins = GenericEvent::new(format, derivation, QueryType::Qry, route).unwrap();
        Self(ins)
    }

    pub fn get_route(&self) -> D {
        self.0.route.clone()
    }
}
