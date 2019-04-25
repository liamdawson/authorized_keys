use super::constants::*;
use super::models::{
    KeyAuthorization, KeyOption, KeyOptions, KeyType, KeysFile, KeysFileLine, PublicKey,
};
use std::str::FromStr;

impl FromStr for KeyType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            ECDSA_SHA2_NISTP256 => Ok(KeyType::EcdsaSha2Nistp256),
            ECDSA_SHA2_NISTP384 => Ok(KeyType::EcdsaSha2Nistp384),
            ECDSA_SHA2_NISTP521 => Ok(KeyType::EcdsaSha2Nistp521),
            SSH_ED25519 => Ok(KeyType::SshEd25519),
            SSH_DSS => Ok(KeyType::SshDss),
            SSH_RSA => Ok(KeyType::SshRsa),
            _ => Err(()),
        }
    }
}

enum ParseError {
    Unmatched(String),
    Incomplete,
}

type ParseResult<'a, T> = Result<(T, &'a [char]), ParseError>;

fn parse_key_type(input: &[char]) -> ParseResult<KeyType> {
    match input.iter().position(|c| c == &' ') {
        Some(index) => {
            let remainder = &input[index..];
            let type_str: String = input[..index].iter().collect();

            let key_type = type_str.parse();

            match key_type {
                Ok(t) => Ok((t, remainder)),
                Err(_) => Err(ParseError::Unmatched(format!(
                    "Unknown key type '{}'.",
                    type_str
                ))),
            }
        }
        None => Err(ParseError::Incomplete),
    }
}

#[inline]
fn parse_base64(input: &[char]) -> ParseResult<String> {
    let str_end = match input
        .iter()
        .position(|c| !(c.is_ascii_alphanumeric() || c == &'/' || c == &'+'))
    {
        Some(mut index) => {
            for _ in 0..2 {
                if input.get(index + 1) == Some(&'=') {
                    index += 1;
                }
            }
            index
        }
        None => input.len(),
    };

    let remainder = &input[str_end..];

    if let Some(c) = remainder.get(0) {
        if !c.is_ascii_whitespace() {
            return Err(ParseError::Unmatched(format!(
                "Unexpected trailing character '{}' on base64 value.",
                c
            )));
        }
    }

    let base64_string: String = input[..str_end].iter().collect();

    match base64_string.len() % 4 {
        0 => Ok((base64_string, remainder)),
        _ => Err(ParseError::Unmatched(
            "Unexpected length of base64 value, expected a multiple of 4.".to_owned(),
        )),
    }
}

fn parse_encoded_key(input: &[char]) -> ParseResult<String> {
    parse_base64(input)
}

fn skip_whitespace(input: &[char]) -> &[char] {
    let skip_to = input
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(0);

    &input[skip_to..]
}

#[inline]
fn skip_char(input: &[char]) -> &[char] {
    if input.is_empty() {
        input
    } else {
        &input[1..]
    }
}

fn parse_public_key(input: &[char]) -> ParseResult<PublicKey> {
    let (key_type, remainder) = parse_key_type(input)?;
    let (encoded_key, remainder) = parse_encoded_key(skip_whitespace(remainder))?;

    Ok((
        PublicKey {
            key_type,
            encoded_key,
        },
        remainder,
    ))
}

fn parse_option_name(input: &[char]) -> ParseResult<String> {
    let name_end = input
        .iter()
        .position(|c| !c.is_ascii_alphanumeric() && c != &'-')
        .unwrap_or_else(|| input.len());

    Ok((input[..name_end].iter().collect(), &input[name_end..]))
}

fn parse_option_value(input: &[char]) -> ParseResult<String> {
    if input.first() != Some(&'"') {
        return Err(ParseError::Unmatched(
            "Unexpected first character in option value.".to_owned(),
        ));
    }

    let input = skip_char(input);
    let mut last_char_slash = false;

    for (ind, c) in input.iter().enumerate() {
        if c == &'"' && !last_char_slash {
            let val = input[..ind].iter().collect();
            let remainder = skip_char(&input[ind..]);

            return Ok((val, remainder));
        }

        last_char_slash = !last_char_slash && c == &'\\';
    }

    Err(ParseError::Incomplete)
}

fn parse_options(input: &[char]) -> ParseResult<Vec<KeyOption>> {
    let mut options: KeyOptions = KeyOptions::new();
    let mut leftovers: &[char] = input;

    while !leftovers.is_empty() {
        let option_name = parse_option_name(leftovers);

        if let Ok((name, remainder)) = option_name {
            leftovers = remainder;
            if leftovers.get(0) == Some(&'=') {
                let (value, remainder) = parse_option_value(&leftovers[1..])?;
                leftovers = remainder;

                options.push((name, Some(value)));
            } else {
                options.push((name, None));
            }

            if leftovers.get(0) == Some(&',') {
                leftovers = skip_char(leftovers);
            } else {
                break;
            }
        } else {
            break;
        }
    }

    Ok((options, leftovers))
}

fn parse_comments(input: &[char]) -> (String, &[char]) {
    let mut comment_end = input
        .iter()
        .position(|c| c == &'\n')
        .unwrap_or_else(|| input.len());

    let remainder = &input[comment_end..];

    // Windows CR-LF handling
    if comment_end >= 2 && input.get(comment_end - 2) == Some(&'\r') {
        comment_end -= 1;
    }

    let comment: String = input[..comment_end].iter().collect();

    (comment, remainder)
}

impl KeyAuthorization {
    fn parse(s: &str) -> Result<Self, String> {
        let chars: Vec<char> = s.chars().collect();
        let public_key_result = parse_public_key(chars.as_slice());
        if let Ok((public_key, remainder)) = public_key_result {
            let (comment, _remainder) = parse_comments(skip_whitespace(remainder));
            Ok(Self {
                options: vec![],
                key: public_key,
                comments: comment,
            })
        } else if let Ok((options, remainder)) = parse_options(chars.as_slice()) {
            if let Ok((public_key, remainder)) = parse_public_key(skip_whitespace(remainder)) {
                let (comments, _remainder) = parse_comments(skip_whitespace(remainder));
                Ok(Self {
                    options,
                    key: public_key,
                    comments,
                })
            } else {
                Err("Could not find a valid public key after the options.".to_owned())
            }
        } else {
            Err("Could not find a valid options string, or public key.".to_owned())
        }
    }
}

impl FromStr for KeyAuthorization {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for KeysFile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines: Vec<KeysFileLine> = Vec::default();

        for (i, line) in s.lines().enumerate() {
            if line.starts_with('#') || line.chars().all(|c| c.is_ascii_whitespace()) {
                lines.push(KeysFileLine::Comment(line.to_owned()));
            } else {
                match KeyAuthorization::parse(line) {
                    Ok(key) => lines.push(KeysFileLine::Key(key)),
                    Err(e) => return Err(format!("parsing failed on line {}: {}", i, e)),
                }
            }
        }

        Ok(Self { lines })
    }
}

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
    fn it_parses_a_basic_keys_file() {
        let file: &str = "ssh-ed25519 AAAAtHUM";
        let expected: Vec<KeysFileLine> = vec![KeysFileLine::Key(KeyAuthorization {
            options: KeyOptions::default(),
            key: PublicKey::new(KeyType::SshEd25519, "AAAAtHUM".to_owned()),
            comments: "".to_owned(),
        })];

        assert_eq!(expected, KeysFile::from_str(file).unwrap().lines);
    }

    #[test]
    fn it_parses_a_basic_keys_file_with_two_comment_lines() {
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
