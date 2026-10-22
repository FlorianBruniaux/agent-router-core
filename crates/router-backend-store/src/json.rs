use serde::Deserialize;

// Independent snapshot size bound; the host-observation parser is limited to
// 4 MiB and must not silently define the durable journal's encoding limit.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> crate::Result<T> {
    if bytes.len() > crate::MAX_SNAPSHOT_BYTES {
        return Err(crate::StoreError::Limit);
    }
    use serde::de::{MapAccess, SeqAccess, Visitor};
    struct StrictValue(serde_json::Value);
    struct StrictVisitor;
    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = StrictValue;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("JSON with unique object keys")
        }
        fn visit_bool<E: serde::de::Error>(
            self,
            value: bool,
        ) -> std::result::Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
            serde_json::Number::from_f64(value)
                .map(|number| StrictValue(number.into()))
                .ok_or_else(|| E::custom("non-finite number"))
        }
        fn visit_str<E: serde::de::Error>(
            self,
            value: &str,
        ) -> std::result::Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_string<E: serde::de::Error>(
            self,
            value: String,
        ) -> std::result::Result<Self::Value, E> {
            Ok(StrictValue(value.into()))
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(StrictValue(serde_json::Value::Null))
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut items = Vec::new();
            while let Some(StrictValue(value)) = seq.next_element()? {
                items.push(value);
            }
            Ok(StrictValue(items.into()))
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut fields = serde_json::Map::new();
            while let Some((key, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
                if fields.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate object key"));
                }
            }
            Ok(StrictValue(fields.into()))
        }
    }
    impl<'de> Deserialize<'de> for StrictValue {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            deserializer.deserialize_any(StrictVisitor)
        }
    }
    let value =
        serde_json::from_slice::<StrictValue>(bytes).map_err(|_| crate::StoreError::Invalid)?;
    serde_json::from_value(value.0).map_err(|_| crate::StoreError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_json_roundtrips_above_host_observation_limit_and_rejects_nested_duplicates() {
        let input = serde_json::json!({"bounded": "x".repeat(4 * 1024 * 1024 + 1)});
        let bytes = serde_json::to_vec(&input).unwrap();
        assert_eq!(parse::<serde_json::Value>(&bytes).unwrap(), input);
        assert!(parse::<serde_json::Value>(br#"{"outer":{"key":1,"key":2}}"#).is_err());
        assert!(parse::<serde_json::Value>(br#"{}{}"#).is_err());
    }
}
