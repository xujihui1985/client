use df_proxy::serve_http;

#[tokio::main]
async fn main() {
    serve_http().await.unwrap();
}