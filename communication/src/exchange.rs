use crate::{GenericEvent, Version};
use said::{derivation::HashFunction, sad::SerializationFormats};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
enum ExchangeType {
    Exn,
}

#[derive(Deserialize, Serialize)]
pub struct ExchangeMessage<V: Version + Serialize + Clone, D: Serialize + Clone>(
    GenericEvent<V, ExchangeType, D>,
);

impl<V: Version + Serialize + Clone, D: Serialize + Clone> ExchangeMessage<V, D> {
    pub fn new(format: SerializationFormats, derivation: HashFunction, route: D) -> Self {
        let ins = GenericEvent::new(format, derivation, ExchangeType::Exn, route).unwrap();
        Self(ins)
    }

    pub fn get_route(&self) -> D {
        self.0.route.clone()
    }

    pub fn encode(&self) -> String {
        String::from_utf8(self.0.encode().unwrap()).unwrap()
    }
}
