use controller::{
    config::ControllerConfig, identifier_controller::IdentifierController, BasicPrefix, Controller,
    CryptoBox, IdentifierPrefix, KeyManager, LocationScheme, Oobi, SelfSigningPrefix,
};
use keri::error::Error;
use std::sync::Arc;
use tempfile::Builder;

#[actix_web::test]
async fn test_messagebox_location() -> Result<(), Error> {
    // Setup first identifier.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller1 = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root.path().to_owned(),
            // transport: transport.clone(),
            ..Default::default()
        })
        .unwrap(),
    );

    let km1 = CryptoBox::new().unwrap();
    let identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller1
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

        let incepted_identifier = controller1
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller1.clone(), None)
    };

    assert!(identifier1.get_kel().is_ok());
    let message_box_id: IdentifierPrefix = "BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-"
        .parse()
        .unwrap();
    let message_box_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://messagebox.sandbox.argo.colossi.network"}}"#,
        message_box_id.to_string()
    ))
    .unwrap();

    // Identifier1 adds messagebox
    identifier1
        .source
        .resolve_oobi(Oobi::Location(message_box_oobi.clone()))
        .await
        .unwrap();

    let schema = identifier1.source.get_loc_schemas(&message_box_id);
    assert_eq!(schema.unwrap()[0], message_box_oobi);

    // Generate reply that contains end role message inside.
    let add_message_box = identifier1.add_messagebox(message_box_id.clone()).unwrap();

    let add_message_box_sig =
        SelfSigningPrefix::Ed25519Sha512(km1.sign(add_message_box.as_bytes()).unwrap());

    // Sign and send message to messagebox.
    identifier1
        .finalize_event(add_message_box.as_bytes(), add_message_box_sig)
        .await
        .unwrap();

    let saved_messagebox_location = identifier1.source.get_messagebox_location(&identifier1.id);
    assert_eq!(saved_messagebox_location.unwrap()[0], message_box_oobi);

    // Setup second identifier.
    let root2 = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller2 = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root2.path().to_owned(),
            // transport: transport.clone(),
            ..Default::default()
        })
        .unwrap(),
    );

    let km2 = CryptoBox::new().unwrap();
    let identifier2 = {
        let pk = BasicPrefix::Ed25519(km2.public_key());
        let npk = BasicPrefix::Ed25519(km2.next_public_key());

        let icp_event = controller2
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes()).unwrap());

        let incepted_identifier = controller2
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller2.clone(), None)
    };

    let end_role_oobi = format!(
        r#"{{"cid":"{}","role":"messagebox","eid":"{}"}}"#,
        &identifier1.id,
        &message_box_id.to_string()
    );
    // Resolve oobis that specify messagebox of identifier1
    identifier2
        .source
        .resolve_oobi(Oobi::Location(message_box_oobi.clone()))
        .await
        .unwrap();
    identifier2
        .source
        .resolve_oobi(serde_json::from_str(&end_role_oobi).unwrap())
        .await
        .unwrap();

    // Check saved identifier1 messagebox information.
    let retrived_messagebox_location = identifier2.source.get_messagebox_location(&identifier1.id);
    assert_eq!(retrived_messagebox_location.unwrap()[0], message_box_oobi);

    Ok(())
}
