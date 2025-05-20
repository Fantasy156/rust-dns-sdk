use serde_json::Value;


pub fn is_null_or_none(value: &Option<Value>) -> bool {
    match value {
        None => true,
        Some(v) => v.is_null(),
    }
}

pub fn option_is_empty<T>(value: &Option<T>) -> bool {
    value.is_none()
}

pub fn is_empty_or_none(list: &Option<Vec<Value>>) -> bool {
    list.as_ref().map(|v| v.is_empty()).unwrap_or(true)
}

pub fn vec_is_empty<T>(v: &Vec<T>) -> bool {
    v.is_empty()
}