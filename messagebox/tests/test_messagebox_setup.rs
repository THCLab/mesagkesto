use keri_sdk::{
    BasicPrefix, IdentifierPrefix, KeyManager, LocationScheme, Oobi, SelfSigningPrefix,
};
use keri_sdk::keri_controller::{config::ControllerConfig, CryptoBox, RedbController};
use keri_sdk::keri_core::{actor::event_generator, error::Error, oobi::Role};
use std::sync::Arc;
use tempfile::Builder;

#[actix_web::test]
async fn test_messagebox_location() -> Result<(), Error> {
    if std::env::var("RUN_NETWORK_TESTS").is_err() {
        return Ok(());
    }
    // Setup first identifier.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller1 = Arc::new(
        RedbController::new(ControllerConfig {
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

        controller1
            .finalize_incept(icp_event.as_bytes(), &signature)
            .unwrap()
    };

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
        .resolve_oobi(&Oobi::Location(message_box_oobi.clone()))
        .await
        .unwrap();

    let schema = identifier1.get_location(&message_box_id);
    assert_eq!(schema.unwrap()[0], message_box_oobi);

    // Generate reply that contains end role message inside.
    let add_message_box = String::from_utf8(
        event_generator::generate_end_role(
            identifier1.id(),
            &message_box_id,
            Role::Messagebox,
            true,
        )
        .encode()
        .unwrap(),
    )
    .unwrap();

    let add_message_box_sig =
        SelfSigningPrefix::Ed25519Sha512(km1.sign(add_message_box.as_bytes()).unwrap());

    // Sign and send message to messagebox.
    identifier1
        .finalize_add_watcher(add_message_box.as_bytes(), add_message_box_sig)
        .await
        .unwrap();

    let saved_messagebox_location =
        identifier1.get_role_location(identifier1.id(), Role::Messagebox);
    assert_eq!(saved_messagebox_location.unwrap()[0], message_box_oobi);

    // Setup second identifier.
    let root2 = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller2 = Arc::new(
        RedbController::new(ControllerConfig {
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

        controller2
            .finalize_incept(icp_event.as_bytes(), &signature)
            .unwrap()
    };

    let end_role_oobi = format!(
        r#"{{"cid":"{}","role":"messagebox","eid":"{}"}}"#,
        identifier1.id(),
        &message_box_id.to_string()
    );
    // Resolve oobis that specify messagebox of identifier1
    identifier2
        .resolve_oobi(&Oobi::Location(message_box_oobi.clone()))
        .await
        .unwrap();
    identifier2
        .resolve_oobi(&serde_json::from_str(&end_role_oobi).unwrap())
        .await
        .unwrap();

    // Check saved identifier1 messagebox information.
    let retrived_messagebox_location =
        identifier2.get_role_location(identifier1.id(), Role::Messagebox);
    assert_eq!(retrived_messagebox_location.unwrap()[0], message_box_oobi);

    Ok(())
}
