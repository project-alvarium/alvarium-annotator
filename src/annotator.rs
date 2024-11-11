use crate::Annotation;

#[async_trait::async_trait]
pub trait Annotator {
    type Error: std::error::Error;
    async fn execute(&mut self, data: &[u8]) -> Result<Annotation, Self::Error>;
}
