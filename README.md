# Alvarium Annotator Core

This crate contains traits, types and constants for use in the Alvarium SDK. 
This includes interface definitions for [Annotators](src/annotator.rs) and 
[Annotations](src/annotations.rs), as well as Hash, Signature, and Stream 
[Providers](src/providers.rs). 

The type definitions such as HashType and KeyAlgorithm provided flexible 
wrappers that can be expanded beyond the preset constants. This allows for 
custom annotators to be developed that still conforms to the interface 
patterns required for use within the SDK. 
