pub mod audio;
// Weighted composite risk score + the reject/captcha thresholds, shared by both
// branches of the validation handler.
pub mod composite;
pub mod handler;
#[cfg(test)]
pub mod mock_validator;
