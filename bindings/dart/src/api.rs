
pub fn register_token(id: String, token: String) -> String {
    let message = messagebox::register_token(id, token);
	message.to_string()

}

pub fn forward_message(receiver_id: String, data: String) -> String {
	let message = messagebox::forward_message(receiver_id, data);
    message.to_string()
}

pub fn query_by_sn(receiver_id: String, sn: usize) -> String {
    let message = messagebox::query_by_sn(receiver_id, sn);
	message.to_string()
}

pub fn query_by_digest(receiver_id: String, digests: Vec<String>) -> String {
    let message = messagebox::query_by_digest(receiver_id, digests);
	message.to_string()
}
