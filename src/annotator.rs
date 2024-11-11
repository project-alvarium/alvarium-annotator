use crate::Annotation;

pub trait Annotator {
    type Error: std::error::Error;
    fn execute(
        &mut self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<Annotation, Self::Error>> + Send + Sync;
}
