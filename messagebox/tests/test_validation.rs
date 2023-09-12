use anyhow::Error;
use messagebox::{
    forward_message, messagebox::MessageBox, query_by_digest, query_by_sn, register_token,
};
use said::derivation::{HashFunction, HashFunctionCode};
use tempfile::Builder;
use url::Url;

#[actix_web::test]
async fn test_validation() -> Result<(), Error> {
    let reg = register_token("Identifier".to_string(), "cEm86d15R7iiArf4J1VMi2:APA91bFozuXaqh6NxqhusEF-7B9RAeVfNbmwHWC4DjwwWMZEzRPcq2ctPQZobKRxSkQtjWp5O0VqktRLAubaNer6rsuzLPz-YaKDQJQlVz1Fp3OHL6UlMutElWzbykdNwI0fENxdFkb6".to_string());
    let exchange = forward_message("Identifier".to_string(), "saved0".to_string());
    let exchange1 = forward_message("Identifier".to_string(), "saved1".to_string());
    let exchange2 = forward_message("Identifier".to_string(), "saved2".to_string());
    let qry = query_by_sn("Identifier".to_string(), 0);

    let register = serde_json::to_string(&reg).unwrap();
    let save = serde_json::to_string(&exchange).unwrap();
    let query = serde_json::to_string(&qry).unwrap();
    dbg!(&register);
    dbg!(&save);
    dbg!(&query);

    // Setup first identifier.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let server_key = "AAAAky1v068:APA91bHHpGtP6M5h3ICFc9AzY35MrkTmjwblkLlEJ1C0yvkrUu7KDkmkXMzPq2q-0o1l49fKxOeDQaKIkZTTEAIX3Jd45j6KNtSempYqop4Psitvz2Ng7iBz-IeS1SGEs1GpnWseJlpP".to_string();

    let messagebox = MessageBox::setup(
        root.path(),
        Url::parse("http:/blabla.com").unwrap(),
        None,
        Some(server_key),
    )
    .await
    .unwrap();

    messagebox
        .validator_handle
        .validate(reg.to_string())
        .await?;
    messagebox
        .validator_handle
        .validate(exchange.to_string())
        .await?;
    messagebox
        .validator_handle
        .validate(exchange1.to_string())
        .await?;
    messagebox
        .validator_handle
        .validate(exchange2.to_string())
        .await?;
    let res = messagebox
        .validator_handle
        .validate(query.to_string())
        .await;
    assert_eq!(
        res?.unwrap(),
        "{\"last_sn\":2,\"messages\":[\"saved0\",\"saved1\",\"saved2\"]}"
    );

    let query = query_by_sn("Identifier".to_string(), 2);
    let res = messagebox
        .validator_handle
        .validate(query.to_string())
        .await;
    assert_eq!(res?.unwrap(), "{\"last_sn\":2,\"messages\":[\"saved2\"]}");

    let query = query_by_sn("Identifier".to_string(), 4);
    let res = messagebox
        .validator_handle
        .validate(query.to_string())
        .await;
    assert_eq!(res?, None);

    let digest_algo: HashFunction = (HashFunctionCode::Blake3_256).into();
    let sai0 = digest_algo.derive("saved0".as_bytes()).to_string();
    let sai1 = digest_algo.derive("saved1".as_bytes()).to_string();
    let qry = query_by_digest("Identifier".to_string(), vec![sai0, sai1]);
    let query_by_digest = serde_json::to_string(&qry).unwrap();
    dbg!(query_by_digest);

    let res = messagebox.validator_handle.validate(qry.to_string()).await;
    assert_eq!(res?, Some("[\"saved0\",\"saved1\"]".to_string()));

    Ok(())
}
