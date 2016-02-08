#[derive(Clone, Debug)]
pub enum StatusCode {
    NormalClosure,
    GoingAway,
    ProtocolError,
    UnsupportedData,
    NoStatusRcvd,
    AbnormalClosure,
    InvalidFramePayloadData,
    PolicyViolation,
    MessageTooBig,
    MandatoryExt,
    InternalServerError,
    TlsHandshake,
}

impl From<StatusCode> for u16 {
    fn from(status: StatusCode) -> u16 {
        match status {
            StatusCode::NormalClosure => 1000,
            StatusCode::GoingAway => 1001,
            StatusCode::ProtocolError => 1002,
            StatusCode::UnsupportedData => 1003,
            StatusCode::NoStatusRcvd => 1005,
            StatusCode::AbnormalClosure => 1006,
            StatusCode::InvalidFramePayloadData => 1007,
            StatusCode::PolicyViolation => 1008,
            StatusCode::MessageTooBig => 1009,
            StatusCode::MandatoryExt => 1010,
            StatusCode::InternalServerError => 1011,
            StatusCode::TlsHandshake => 1015,
        }
    }
}

impl<'a> From<StatusCode> for &'a str {
    fn from(status: StatusCode) -> &'a str {
        match status {
            StatusCode::NormalClosure => "Normal Closure",
            StatusCode::GoingAway => "Going Away",
            StatusCode::ProtocolError => "Protocol error",
            StatusCode::UnsupportedData => "Unsupported Data",
            StatusCode::NoStatusRcvd => "No Status Rcvd",
            StatusCode::AbnormalClosure => "Abnormal Closure",
            StatusCode::InvalidFramePayloadData => "Invalid frame payload data",
            StatusCode::PolicyViolation => "Policy Violation",
            StatusCode::MessageTooBig => "Message Too Big",
            StatusCode::MandatoryExt => "Mandatory Ext.",
            StatusCode::InternalServerError => "Internal Server Error",
            StatusCode::TlsHandshake => "TLS handshake",
        }
    }
}
