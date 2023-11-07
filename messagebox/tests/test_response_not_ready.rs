#[cfg(test)]
pub mod test {
    use std::{path::Path, sync::Arc, time::Duration};

    use controller::{
        config::ControllerConfig, identifier_controller::IdentifierController, BasicPrefix,
        Controller, CryptoBox, KeyManager, LocationScheme, SelfSigningPrefix,
    };
    use messagebox::{forward_message, messagebox::MessageBox, query_by_sn, MessageboxError};
    use serde_json::json;
    use tempfile::Builder;
    use tokio::time::sleep;

    async fn setup_identifier(km: &CryptoBox, db_path: &Path) -> IdentifierController {
        // Setup signer
        let config = ControllerConfig {
            db_path: db_path.into(),
            ..Default::default()
        };
        let cont = Arc::new(Controller::new(config).unwrap());
        let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#;
        // let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#;
        let witness_oobi: LocationScheme = serde_json::from_str(witness_oobi_st).unwrap();
        let witness_id: BasicPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"
            .parse()
            .unwrap();

        // Incept signer identifier and publish kel to witness.
        let signing_identifier = {
            let pk = BasicPrefix::Ed25519(km.public_key());
            let npk = BasicPrefix::Ed25519(km.next_public_key());

            let icp_event = cont
                .incept(vec![pk], vec![npk], vec![witness_oobi], 1)
                .await
                .unwrap();
            let signature =
                SelfSigningPrefix::Ed25519Sha512(km.sign(icp_event.as_bytes()).unwrap());

            let incepted_identifier = cont
                .finalize_inception(icp_event.as_bytes(), &signature)
                .await
                .unwrap();
            IdentifierController::new(incepted_identifier, cont.clone(), None)
        };

        signing_identifier.notify_witnesses().await.unwrap();

        // Quering mailbox to get receipts
        let query = signing_identifier
            .query_mailbox(&signing_identifier.id, &[witness_id.clone()])
            .unwrap();

        // Query with wrong signature
        {
            let qry = query[0].clone();
            let sig = SelfSigningPrefix::Ed25519Sha512(km.sign(&qry.encode().unwrap()).unwrap());
            signing_identifier
                .finalize_query(vec![(qry, sig)])
                .await
                .unwrap();
        };
        signing_identifier
    }

    async fn update_identifier(id: &IdentifierController, km: &CryptoBox, witness_id: BasicPrefix) {
        let pk = BasicPrefix::Ed25519(km.public_key());
        let npk = BasicPrefix::Ed25519(km.next_public_key());

        let rot_event = id
            .rotate(vec![pk], vec![npk], vec![], vec![], 1)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(rot_event.as_bytes()).unwrap());
        id.finalize_event(rot_event.as_bytes(), signature)
            .await
            .unwrap();
        id.notify_witnesses().await.unwrap();

        // Publishing rotation after messagebox resolve oobi, to let him retrieve it from watcher.
        // Quering mailbox to get receipts
        let query = id.query_mailbox(&id.id, &[witness_id.clone()]).unwrap();

        // Query with wrong signature
        {
            let qry = query[0].clone();
            let sig = SelfSigningPrefix::Ed25519Sha512(km.sign(&qry.encode().unwrap()).unwrap());
            id.finalize_query(vec![(qry, sig)]).await.unwrap();
        }
    }

    #[actix_web::test]
    async fn test_response_not_ready() {
        let inserting_id_db = Builder::new().prefix("test-db1").tempdir().unwrap();
        let quering_id_db = Builder::new().prefix("test-db2").tempdir().unwrap();
        let messagebox_db = Builder::new()
            .prefix("test-messagebox-db")
            .tempdir()
            .unwrap();
        let messagebox_oobi_db = Builder::new().prefix("test-oobi-db").tempdir().unwrap();

        // Setup signer
        let mut km1 = CryptoBox::new().unwrap();
        let km2 = CryptoBox::new().unwrap();
        let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#;
        // let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#;
        let witness_id: BasicPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"
            .parse()
            .unwrap();
        let querying_identifier = setup_identifier(&km1, quering_id_db.path()).await;
        let inserting_identifier = setup_identifier(&km2, inserting_id_db.path()).await;

        let querying_oobi_str = json!({"cid": &querying_identifier.id ,"role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}).to_string();
        let inserting_oobi_str = json!({"cid": &inserting_identifier.id ,"role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}).to_string();
        let watcher_oobi = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}"#).unwrap();

        // Setup messagebox
        let msg_box = MessageBox::setup(messagebox_db.path(), messagebox_oobi_db.path(), watcher_oobi, "http://url.com".parse().unwrap(), None, Some("AAAAky1v068:APA91bHHpGtP6M5h3ICFc9AzY35MrkTmjwblkLlEJ1C0yvkrUu7KDkmkXMzPq2q-0o1l49fKxOeDQaKIkZTTEAIX3Jd45j6KNtSempYqop4Psitvz2Ng7iBz-IeS1SGEs1GpnWseJlpP".to_string())).await.unwrap();

        msg_box
            .resolve_oobi(witness_oobi_st.to_string())
            .await
            .unwrap();
        msg_box
            .resolve_oobi(inserting_oobi_str.to_string())
            .await
            .unwrap();

        msg_box
            .resolve_oobi(querying_oobi_str.clone())
            .await
            .unwrap();

        // Rotate querying identifier
        km1.rotate().unwrap();
        update_identifier(&querying_identifier, &km1, witness_id).await;

        // Save message from inserting identifier.
        let exn_msg = forward_message("Identifier".to_string(), "saved0".to_string());
        let signature =
            SelfSigningPrefix::Ed25519Sha512(km2.sign(exn_msg.to_string().as_bytes()).unwrap());
        let signed_exn = inserting_identifier
            .sign_to_cesr(&exn_msg.to_string(), signature, 0)
            .unwrap();

        let r = msg_box.process_message(signed_exn).await;
        assert!(r.is_ok());

        let qry_msg = query_by_sn("Identifier".to_string(), 0);
        let signature =
            SelfSigningPrefix::Ed25519Sha512(km1.sign(qry_msg.to_string().as_bytes()).unwrap());
        let signed_query = querying_identifier
            .sign_to_cesr(&qry_msg.to_string(), signature, 0)
            .unwrap();

        let r = msg_box.process_message(signed_query).await;
        dbg!(&r);
        if let Err(MessageboxError::ResponseNotReady(sai)) = r {
            sleep(Duration::from_secs(5)).await;
            let response = msg_box.get_responses(sai).await;
            assert!(response.is_some());
        } else {
            unreachable!()
        };
    }
}
