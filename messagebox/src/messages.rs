use communication::{exchange::ExchangeMessage, Version, query::QueryMessage};
use said::{version::SerializationInfo, sad::SerializationFormats};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageType {
    Qry(Query),
    Exn(Exchange),
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct MessageboxInfo(SerializationInfo);


impl Version for MessageboxInfo {
    fn encode<T: Serialize>(&self, d: &T) -> Vec<u8> {
       self.0.serialize(d).unwrap()
    }

    fn new(len: usize) -> Self {
        MessageboxInfo(SerializationInfo::new("MSGB".to_string(), 0, 0, SerializationFormats::JSON, len))
    }
}

pub type Exchange = ExchangeMessage<MessageboxInfo, ExchangeRoute>; 
pub type Query = QueryMessage<MessageboxInfo, QueryRoute>;



#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum QueryRoute {
    ByDigest { i: String, a: Vec<String> },
    BySn { i: String, s: usize },
}

impl ToString for MessageType {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "r")]
#[serde(rename_all = "lowercase")]
pub enum ExchangeRoute {
    // Forward `a` to other identifier
    Fwd {
        i: String,
        a: String,
    },
    // Save firebase token (f) of given identifier (i)
    #[serde(rename = "/auth/f")]
    SetFirebase {
        i: String,
        f: String,
    },
}

#[test]
pub fn test_parse_query() {
    let msg = "{\"v\":\"MSGB00JSON0000cb_\",\"t\":\"qry\",\"d\":\"EJTBf0KYvOQUXEbIABTmzGkxgCEvspZmBfU9qod-xkga\",\"i\":\"Identifier\",\"a\":[\"EKJXRYElzvGAJ7fttFjUJAfy0esjx0-tQFt7ynwJ4C82\",\"EFzNKZeXsHBij6mgLLsl7XkW7ThfvSrC5oDh8fj9lTVO\"]}";
    let parsed = serde_json::from_str::<MessageType>(msg);
    assert!(parsed.is_ok());
}

#[test]
pub fn test_parse_exchange() {
    let msg = "{\"v\":\"MSGB00JSON00007e_\",\"t\":\"exn\",\"d\":\"ENi_QoR0Wym2tT7MXk8JINs1EFa9hm2pEsj7HgEVDILH\",\"r\":\"fwd\",\"i\":\"Identifier\",\"a\":\"saved2\"}";
    let parsed = serde_json::from_str::<MessageType>(msg);
    assert!(parsed.is_ok());
}

#[test]
pub fn test_exchange() {
    use said::derivation::{HashFunction, HashFunctionCode};
    let h = HashFunction::from(HashFunctionCode::Blake3_256);
    let r = ExchangeRoute::SetFirebase { i: "id".to_string(), f: "token".to_string() };
    let exn = Exchange::new(said::sad::SerializationFormats::JSON, h, r);

    assert_eq!(r#"{"v":"MSGB00JSON000079_","t":"exn","d":"EPPfkHqNrgbVEk8VtSq4dWRLZl5xjUz10YgEHfS2HWsd","r":"/auth/f","i":"id","f":"token"}"#, &exn.encode());
}