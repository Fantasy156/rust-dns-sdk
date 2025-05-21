#[macro_export]
/// The `extract_params!` macro is used to extract fields from a builder and generate a struct instance containing those field values.
///
/// This macro supports:
/// - Extracting required fields, with type conversion and validation
/// - Extracting optional fields, using a default value if they don't exist
/// - Renaming fields to specified key names for serialization
///
/// # Usage
///
/// ```rust
/// extract_params!(builder, StructName, {
///     required field1: Type => "json_key1",
///     optional field2: Type = default_value => "json_key2"
/// });
/// ```
///
/// Where:
/// - `builder` is the builder object containing the fields
/// - `StructName` is the name of the struct to be generated
/// - `field1`, `field2`, etc., are the field names in the builder
/// - `Type` can be `String`, `&str`, `u32`, or `u64`
/// - `json_keyX` is the key name for the field in JSON
/// - `default_value` is the default value for optional fields
///
macro_rules! extract_params {
    // Parse type helper: match with conversion or without conversion, conversion must be wrapped in parentheses
    (@type ( $src_ty:ident as $conv_ty:ty )) => { $conv_ty };
    (@type $ty:ident) => {
        $ty
    };

    // Parse required field, with conversion (parentheses wrapped)
    (@extract_required $builder:expr, $field:ident, ( $src_ty:ident as $conv_ty:ty )) => {{
        let val = $builder.$field.clone().ok_or_else(|| format!("{} is required", stringify!($field)))?;
        val.parse::<$conv_ty>().map_err(|e| format!("{} parse failed: {}", stringify!($field), e))?
    }};
    // Parse required field, without conversion
    (@extract_required $builder:expr, $field:ident, $ty:ident) => {
        extract_params!(@extract_required_no_conv $builder, $field, $ty)
    };

    // Parse required field, no conversion implementations for various types
    (@extract_required_no_conv $builder:expr, $field:ident, String) => {
        $builder.$field.clone().ok_or_else(|| format!("{} is required", stringify!($field)))?
    };
    (@extract_required_no_conv $builder:expr, $field:ident, &str) => {
        $builder.$field.clone().as_deref().ok_or_else(|| format!("{} is required", stringify!($field)))?.to_string()
    };
    (@extract_required_no_conv $builder:expr, $field:ident, u32) => {
        $builder.$field.ok_or_else(|| format!("{} is required", stringify!($field)))?
    };
    (@extract_required_no_conv $builder:expr, $field:ident, u64) => {
        $builder.$field.ok_or_else(|| format!("{} is required", stringify!($field)))?
    };
    (@extract_required_no_conv $builder:expr, $field:ident, bool) => {
        $builder.$field.ok_or_else(|| format!("{} is required", stringify!($field)))?
    };

    // Parse optional field, with conversion (parentheses wrapped)
    (@extract_optional $builder:expr, $field:ident, ( $src_ty:ident as $conv_ty:ty ), $default:expr) => {{
        match $builder.$field.clone() {
            Some(val) => val.parse::<$conv_ty>().map_err(|e| format!("{} parse failed: {}", stringify!($field), e))?,
            None => $default,
        }
    }};
    // Parse optional field, without conversion
    (@extract_optional $builder:expr, $field:ident, String, $default:expr) => {
        $builder.$field.clone().unwrap_or_else(|| $default.into())
    };
    (@extract_optional $builder:expr, $field:ident, &str, $default:expr) => {
        $builder.$field.clone().as_deref().map(|s| s.to_string()).unwrap_or_else(|| $default.into())
    };
    (@extract_optional $builder:expr, $field:ident, u32, $default:expr) => {
        $builder.$field.unwrap_or($default)
    };
    (@extract_optional $builder:expr, $field:ident, u64, $default:expr) => {
        $builder.$field.unwrap_or($default)
    };
    (@extract_optional $builder:expr, $field:ident, bool, $default:expr) => {
        $builder.$field.unwrap_or($default)
    };
    (@extract_optional $builder:expr, $field:ident, $ty:ident, $default:expr) => {{
        $builder.$field.clone().unwrap_or_else(|| $default.into())
    }};

    // Main macro
    (
        $builder:expr,
        $struct_name:ident,
        {
            $( required $req_field:ident : $req_ty:tt => $req_key:literal ),* $(,)*
            $( optional $opt_field:ident : $opt_ty:tt = $opt_default:expr => $opt_key:literal ),* $(,)*
        }
    ) => {{
        #[derive(Debug, serde::Serialize)]
        struct $struct_name {
            $(
                #[serde(rename = $req_key)]
                $req_field: extract_params!(@type $req_ty),
            )*
            $(
                #[serde(rename = $opt_key)]
                $opt_field: extract_params!(@type $opt_ty),
            )*
        }

        $struct_name {
            $(
                $req_field: extract_params!(@extract_required $builder, $req_field, $req_ty),
            )*
            $(
                $opt_field: extract_params!(@extract_optional $builder, $opt_field, $opt_ty, $opt_default),
            )*
        }
    }};
}