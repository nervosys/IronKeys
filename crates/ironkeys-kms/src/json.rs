//! IronCrypto's JSON reader, with lookups that yield null when a member is
//! absent, as the AWS response handling expects.
use ic_json::Json;

static NULL: Json = Json::Null;

/// Parse UTF-8 JSON.
pub(crate) fn parse(data: &[u8]) -> Result<Json, ()> {
    ic_json::parse(std::str::from_utf8(data).map_err(|_| ())?).map_err(|_| ())
}

/// Member lookup that never fails.
pub(crate) trait At {
    /// The member `key`, or null when this is not an object or has no such
    /// member.
    fn at(&self, key: &str) -> &Json;
}

impl At for Json {
    fn at(&self, key: &str) -> &Json {
        self.get(key).unwrap_or(&NULL)
    }
}
