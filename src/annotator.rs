use crate::Annotation;

pub trait Annotator {
    type Error: std::error::Error;
    fn execute(&mut self, data: &[u8]) -> Result<Annotation, Self::Error>;
}
