use error::Error;
use said::{SelfAddressingIdentifier, sad::{SerializationFormats, SAD}, derivation::HashFunction};
use serde::{Deserialize, Serialize};

pub mod exchange;
pub mod query;
pub mod error;

pub trait Version: Default {
	fn encode<T: Serialize>(&self, d: &T) -> Vec<u8>;
	fn new(len: usize) -> Self;
}

/// Encapsulate logic common for every exchange and query messages, i.e.
/// computing digest and updates version.
#[derive(Deserialize, Serialize, SAD, Debug)]
pub(crate) struct GenericEvent<V: Version + Serialize + Clone,T: Clone + Serialize, D: Serialize + Clone> {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
    pub serialization_info: V,

    #[serde(rename = "t")]
	event_type: T,

    /// Digest of the event
    ///
    /// While computing the digest, this field is replaced with sequence of `#`,
    /// its length depends on derivation type. Then it is replaced by computed
    /// SAI.
	/// 
	#[said]
    #[serde(rename = "d")]
    pub digest: Option<SelfAddressingIdentifier>,

    #[serde(flatten)]
    pub route: D,
}

impl<V: Version + Serialize + Clone, T: Clone + Serialize, D: Serialize + Clone> GenericEvent<V, T, D> {

pub fn new(
        format: SerializationFormats,
        derivation: HashFunction,
		t: T,
        event: D,
    ) -> Result<Self, Error> {
        let tmp_serialization_info = V::default();

        let mut tmp_self = Self {
            serialization_info: tmp_serialization_info,
			event_type: t,
            digest: None,
            route: event,
        };
        let encoded = tmp_self.derivation_data();

        let event_len = encoded.len();
		let new_version = V::new(event_len);
		tmp_self.serialization_info = new_version;
        tmp_self.compute_digest();
        Ok(tmp_self)
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.serialization_info.encode(&self))
    }
}