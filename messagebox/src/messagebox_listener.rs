use crate::messagebox::MessageBox;
use actix_web::{
    dev::Server, http::StatusCode, web::Data, App, HttpResponse, HttpServer, ResponseError,
};
use keri::database::DbError;
use std::{net::ToSocketAddrs, sync::Arc};

pub struct MessageBoxListener {
    pub messagebox: MessageBox,
}

impl MessageBoxListener {
    pub fn listen_http(&self, addr: impl ToSocketAddrs) -> Server {
        let state = Data::new(Arc::new(self.messagebox.clone()));
        HttpServer::new(move || {
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
                    actix_web::web::post().to(http_handlers::validate_message),
                )
        })
        .bind(addr)
        .unwrap()
        .run()
    }
}

mod http_handlers {
    use std::sync::Arc;

    use crate::messagebox::MessageBox;
    use actix_web::{http::header::ContentType, web, HttpResponse};
    use keri::{
        actor::parse_reply_stream,
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        prefix::IdentifierPrefix,
        query::reply_event::SignedReply,
    };

    use super::ApiError;

    pub fn oobis_to_cesr_stream(oobis: impl Iterator<Item = SignedReply>) -> Vec<u8> {
        oobis
            .flat_map(|sr| {
                let sed = Message::Op(Op::Reply(sr));
                sed.to_cesr().unwrap()
            })
            .collect::<Vec<_>>()
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

        let oobis: Vec<u8> = oobis_to_cesr_stream(loc_scheme.into_iter());

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let (cid, role, eid) = path.into_inner();

        let end_role_feature = data.oobi_handle.get_role_oobi(cid, role, eid.clone());
        let loc_scheme_feature = data.get_loc_scheme_for_id(&eid);
        let (end_role, loc_scheme) = tokio::join!(end_role_feature, loc_scheme_feature);
        let oobis = oobis_to_cesr_stream(
            end_role
                .unwrap()
                .into_iter()
                .chain(loc_scheme?.unwrap_or_default().into_iter()),
        );

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn validate_message(
        body: String,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        Ok(match data.validator_handle.validate(body).await {
            Some(response) => HttpResponse::Ok().body(response),
            None => HttpResponse::Ok().finish(),
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
        let replys = parse_reply_stream(&body).unwrap();
        data.oobi_handle.register(replys).await;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    KeriError(#[from] keri::error::Error),
    #[error(transparent)]
    KeriDbError(#[from] DbError),
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}
