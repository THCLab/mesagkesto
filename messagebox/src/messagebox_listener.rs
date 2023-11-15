use crate::{messagebox::MessageBox, MessageboxError};
use actix_web::{
    dev::Server, http::StatusCode, web::Data, App, HttpResponse, HttpServer, ResponseError,
};
use anyhow::Result;
use controller::{messagebox, IdentifierPrefix};
use keri::{database::DbError, oobi::Role};
use said::SelfAddressingIdentifier;
use std::{net::ToSocketAddrs, sync::Arc};

pub struct MessageBoxListener {
    pub messagebox: MessageBox,
}

impl MessageBoxListener {
    pub fn listen_http(&self, addr: impl ToSocketAddrs) -> Result<Server> {
        let state = Data::new(Arc::new(self.messagebox.clone()));
        Ok(HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .route(
                    "/introduce",
                    actix_web::web::get().to(http_handlers::introduce),
                )
                .route(
                    "/oobi/{id}",
                    actix_web::web::get().to(http_handlers::get_eid_oobi),
                )
                .route(
                    "/oobi/{cid}/{role}/{eid}",
                    actix_web::web::get().to(http_handlers::get_cid_oobi),
                )
                .route(
                    "/register",
                    actix_web::web::post().to(http_handlers::register),
                )
                .route(
                    "/",
                    actix_web::web::post().to(http_handlers::process_message),
                )
                .route(
                    "/resolve",
                    actix_web::web::post().to(http_handlers::resolve_oobi),
                )
                .route(
                    "/messages/{said}",
                    actix_web::web::get().to(http_handlers::get_response),
                )
        })
        .bind(addr)?
        .run())
    }
}

mod http_handlers {
    use std::sync::Arc;

    use crate::{messagebox::MessageBox, MessageboxError};
    use actix_web::{http::header::ContentType, web, HttpResponse};
    use keri::{
        actor::parse_reply_stream,
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        prefix::IdentifierPrefix,
        query::reply_event::SignedReply,
    };
    use said::SelfAddressingIdentifier;

    use super::ApiError;

    fn oobis_to_cesr_stream(
        oobis: &mut impl Iterator<Item = SignedReply>,
    ) -> Result<Vec<u8>, ApiError> {
        oobis.try_fold(vec![], |mut acc, sr| {
            let mut oobi = Message::Op(Op::Reply(sr)).to_cesr()?;

            acc.append(&mut oobi);
            Ok(acc)
        })
    }

    pub async fn introduce(data: web::Data<Arc<MessageBox>>) -> Result<HttpResponse, ApiError> {
        Ok(HttpResponse::Ok().json(data.oobi()))
    }

    /// Returns stream of signed reply messages that has endpoint identifier
    /// location schemas inside.
    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let loc_scheme = data.get_loc_scheme_for_id(&eid).await?.unwrap_or_default();

        let oobis: Vec<u8> = oobis_to_cesr_stream(&mut loc_scheme.into_iter())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(oobis))
    }

    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let (cid, role, eid) = path.into_inner();

        let end_role_feature =
            data.oobi_handle
                .get_role_oobi(cid.clone(), role.clone(), eid.clone());
        let loc_scheme_feature = data.get_loc_scheme_for_id(&eid);
        let (end_role, loc_scheme) = tokio::join!(end_role_feature, loc_scheme_feature);
        let oobis = oobis_to_cesr_stream(
            &mut end_role
                .ok_or(ApiError::MissingEndRoleOobi(cid, role))?
                .into_iter()
                .chain(loc_scheme?.unwrap_or_default().into_iter()),
        )?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(oobis))
    }

    pub async fn process_message(
        body: String,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        Ok(match data.process_message(body).await {
            Ok(Some(response)) => HttpResponse::Ok().body(response),
            Ok(None) => HttpResponse::Ok().finish(),
            Err(MessageboxError::VerificationFailure) => HttpResponse::Unauthorized().finish(),
            Err(MessageboxError::ResponseNotReady(said)) => {
                let message = format!(
                    "Missing event, need to ask later on `/messages/{}` endpoint.",
                    said
                );
                HttpResponse::Accepted().body(message)
            }
            Err(MessageboxError::MissingOobi) => {
                let message =
                    "Missing oobi, need to be provided to `/resolve` endpoint.".to_string();
                HttpResponse::UnprocessableEntity().body(message)
            }
            Err(err) => {
                let message = format!("Message ignored due to error: {}", &err);
                HttpResponse::BadRequest().body(message)
            }
        })
    }

    pub async fn register(
        body: web::Bytes,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        println!(
            "\nGot oobis to process: \n{}",
            String::from_utf8_lossy(&body)
        );
        let replys = parse_reply_stream(&body)?;
        data.oobi_handle.register(replys).await;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn resolve_oobi(
        body: web::Bytes,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let oobi_str = String::from_utf8(body.to_vec()).map_err(|e| ApiError::Unparsable)?;
        println!("\nGot oobi to resolve: \n{}", &oobi_str);

        data.resolve_oobi(oobi_str.clone()).await?;

        Ok(HttpResponse::Ok().finish())
    }

    pub async fn get_response(
        said: web::Path<SelfAddressingIdentifier>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        println!("\nRequest responses for: \n{}", &said.to_string());
        let sai = said.into_inner();
        data.response_handle
            .get_by_digest(sai.clone())
            .await
            .ok_or(ApiError::UnknownResponse(sai))?;

        Ok(HttpResponse::Ok().finish())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    KeriError(#[from] keri::error::Error),
    #[error(transparent)]
    KeriDbError(#[from] DbError),
    #[error(transparent)]
    MessageboxError(#[from] MessageboxError),
    #[error("Can't be parsed")]
    Unparsable,
    #[error("No end role oobi of identifier: {0}, {1:?}")]
    MissingEndRoleOobi(IdentifierPrefix, Role),
    #[error("Unknown response said: {0}")]
    UnknownResponse(SelfAddressingIdentifier),
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}
