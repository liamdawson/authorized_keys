use super::models::{
    KeyAuthorization, KeyOption, KeyOptions, KeyType, KeysFile, KeysFileLine, PublicKey,
};
use nom::is_alphanumeric;
use std::str::FromStr;

// const BASE64_CHAR: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=";
// const IDENT_CHAR: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

const ASCII_DASH: u8 = '-' as u8;
const ASCII_SLASH: u8 = '/' as u8;
const ASCII_PLUS: u8 = '+' as u8;
const ASCII_EQUALS: u8 = '=' as u8;

named!(parse_dashed_ident<&str, &str>, take_while1!(|c: char| c.is_ascii_alphanumeric() || c == '-'));

named!(parse_opt_name<&str, &str>, call!(parse_dashed_ident));
named!(
    parse_opt_value<&str, &str>,
    delimited!(
        char!('"'),
        // allow escaped quotes and backslashes, and take everything
        // that isn't an unescaped quote, or a linefeed
        escaped!(is_not!("\""), '\\', one_of!("\"\\")),
        char!('"')
    )
);

named!(
    parse_opt_with_value<&str, (&str, Option<&str>)>,
    separated_pair!(parse_opt_name, char!('='), map!(parse_opt_value, |v| Some(v)))
);

named!(
    parse_opt_by_name<&str, (&str, Option<&str>)>,
    map!(parse_opt_name, |n| (n, None))
);

named!(parse_key_opt<&str, (&str, Option<&str>)>, alt!(parse_opt_with_value | parse_opt_by_name));
named!(parse_key_opts<&str, Vec<(&str, Option<&str>)>>, separated_list!(tag!(","), parse_key_opt));

named!(parse_key_type<&str, KeyType>, flat_map!(parse_dashed_ident, parse_to!(KeyType)));
// TODO: really validate the base64 format
named!(parse_base64<&str, &str>, take_while1!(|c:char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
named!(public_key<&str, PublicKey>, do_parse!(key_type: parse_key_type >> ws!() >> encoded_key: parse_base64 >> (PublicKey {
    key_type,
    encoded_key: encoded_key.to_owned()
})));

// named!(option_value, many_till!()

#[cfg(test)]
mod tests {
    use super::*;

    fn key_option(name: &str, val: Option<&str>) -> KeyOption {
        (name.to_owned(), val.map(std::string::ToString::to_string))
    }

    #[test]
    fn it_parses_a_minimal_key() {
        let key_str: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM";

        let key = KeyAuthorization::from_str(key_str).expect("should parse key successfully");

        assert_eq!(KeyType::SshEd25519, key.key.key_type);
        assert_eq!(
            "AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM",
            key.key.encoded_key
        );
    }

    #[test]
    fn it_parses_a_key_with_a_comment_through_consecutive_spaces() {
        let key_str: &str = "ssh-ed25519   AAAAtHUM   hello, world!";

        let key = KeyAuthorization::from_str(key_str).expect("should parse key successfully");

        assert_eq!("hello, world!", key.comments);
    }

    #[test]
    fn it_parses_a_key_with_a_comment() {
        let key_str: &str = "ssh-ed25519 AAAAtHUM hello, world!";

        let key = KeyAuthorization::from_str(key_str).expect("should parse key successfully");

        assert_eq!("hello, world!", key.comments);
    }

    #[test]
    fn it_parses_a_name_option() {
        let key_str: &str = "no-agent-forwarding ssh-ed25519 AAAAtHUM";

        let key = KeyAuthorization::from_str(key_str).expect("should parse key successfully");

        assert_eq!(vec![("no-agent-forwarding".to_owned(), None)], key.options);
    }

    #[test]
    fn it_parses_a_value_option() {
        let key_str: &str = r#"command="echo hello" ssh-ed25519 AAAAtHUM"#;

        let key = KeyAuthorization::from_str(key_str).expect("should parse key successfully");

        assert_eq!(
            vec![("command".to_owned(), Some("echo hello".to_owned()))],
            key.options
        );
    }

    #[test]
    fn it_parses_a_complex_line() {
        let key_str: &str =
            r#"no-agent-forwarding,command="echo \"hello\"",restrict ssh-ed25519 AAAAtHUM comment value here"#;

        let key = KeyAuthorization::from_str(key_str).expect("should parse key successfully");

        assert_eq!(
            vec![
                key_option("no-agent-forwarding", None),
                key_option("command", Some(r#"echo \"hello\""#)),
                key_option("restrict", None)
            ],
            key.options
        );

        assert_eq!(KeyType::SshEd25519, key.key.key_type);
        assert_eq!("AAAAtHUM", key.key.encoded_key);
        assert_eq!("comment value here", key.comments);
    }

    #[test]
    fn it_parses_with_empty_option_value() {
        let key_str = r#"command="" ssh-rsa AAAAtHUM"#;
        let expected = vec![key_option("command", Some(""))];

        assert_eq!(
            expected,
            KeyAuthorization::parse(key_str)
                .expect("failed to parse valid key line")
                .options
        );
    }

    #[test]
    fn it_parses_an_empty_keys_file() {
        let file: &str = "";
        let expected: Vec<KeysFileLine> = vec![];

        assert_eq!(expected, KeysFile::from_str(file).unwrap().lines);
    }

    #[test]
    fn it_parses_an_basic_keys_file() {
        let file: &str = "ssh-ed25519 AAAAtHUM";
        let expected: Vec<KeysFileLine> = vec![KeysFileLine::Key(KeyAuthorization {
            options: KeyOptions::default(),
            key: PublicKey::new(KeyType::SshEd25519, "AAAAtHUM".to_owned()),
            comments: "".to_owned(),
        })];

        assert_eq!(expected, KeysFile::from_str(file).unwrap().lines);
    }

    #[test]
    fn it_parses_an_basic_keys_file_with_two_comment_lines() {
        let file: &str = "# hello, world!\n\nssh-ed25519 AAAAtHUM";
        let expected: Vec<KeysFileLine> = vec![
            KeysFileLine::Comment("# hello, world!".to_owned()),
            KeysFileLine::Comment("".to_owned()),
            KeysFileLine::Key(KeyAuthorization {
                options: KeyOptions::default(),
                key: PublicKey::new(KeyType::SshEd25519, "AAAAtHUM".to_owned()),
                comments: "".to_owned(),
            }),
        ];

        assert_eq!(expected, KeysFile::from_str(file).unwrap().lines);
    }
}
