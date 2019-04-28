use super::super::models::{KeyOption, KeyOptions, KeyType, PublicKey};
use super::atoms::*;
use super::parts::*;
use std::borrow::ToOwned;

named!(
    pub(crate) parse_mapped_key_type<&str, KeyType>,
    flat_map!(parse_dashed_ident, parse_to!(KeyType))
);

named!(
    pub(crate) parse_mapped_public_key<&str, PublicKey>,
    do_parse!(
        key_type: parse_mapped_key_type >>
        parse_whitespace >>
        encoded_key: parse_base64 >>
        (PublicKey {
            key_type,
            encoded_key: encoded_key.to_owned()
        })
    )
);

fn raw_key_option_to_mapped_key_option((name, value): &(&str, Option<&str>)) -> KeyOption {
    (name.to_string(), value.map(ToOwned::to_owned))
}

named!(
    pub(crate) parse_mapped_key_options<&str, KeyOptions>,
    map!(parse_options, |opts| opts.iter().map(raw_key_option_to_mapped_key_option).collect())
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_key_types() {
        let test_val = KeyType::SshEd25519.to_string();

        let (_, actual) = parse_mapped_key_type(&test_val).unwrap();

        assert_eq!(actual, KeyType::SshEd25519);
    }

    #[test]
    fn it_parses_public_keys() {
        let test_cases = &[
            (
                "ssh-ed25519 foobar==",
                PublicKey {
                    key_type: KeyType::SshEd25519,
                    encoded_key: "foobar==".to_owned(),
                },
            ),
            (
                "ecdsa-sha2-nistp521 istestbase64",
                PublicKey {
                    key_type: KeyType::EcdsaSha2Nistp521,
                    encoded_key: "istestbase64".to_owned(),
                },
            ),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_mapped_public_key(test_case);

            assert!(
                res.is_ok(),
                "case '{}' failed: {}",
                test_case,
                res.unwrap_err()
            );

            if let Ok((_, actual)) = res {
                assert_eq!(*expected, actual);
            }
        }
    }

    #[test]
    fn it_parses_option_lists() {
        let test_cases = &[
            ("restrict", vec![("restrict".to_owned(), None)]),
            (
                "restrict,command=\"uptime\"",
                vec![
                    ("restrict".to_owned(), None),
                    ("command".to_owned(), Some("uptime".to_owned())),
                ],
            ),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_mapped_key_options(test_case);

            assert!(
                res.is_ok(),
                "case '{}' failed: {}",
                test_case,
                res.unwrap_err()
            );

            if let Ok((_, actual)) = res {
                assert_eq!(*expected, actual);
            }
        }
    }
}
