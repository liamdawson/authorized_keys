use super::super::models::{KeyAuthorization, KeyOptions};
use super::atoms::{parse_line_remainder, parse_whitespace};
use super::mapped::*;

named!(
    pub(crate) parse_optionless_key_authorization<&str, KeyAuthorization>,
    do_parse!(
        public_key: parse_mapped_public_key >>
        comments: parse_line_remainder >>
        (KeyAuthorization {
            options: KeyOptions::new(),
            key: public_key,
            comments: comments.trim_start().to_owned()
        })
    )
);

named!(
    pub(crate) parse_optioned_key_authorization<&str, KeyAuthorization>,
    do_parse!(
        options: parse_mapped_key_options >>
        parse_whitespace >>
        public_key: parse_mapped_public_key >>
        comments: parse_line_remainder >>
        (KeyAuthorization {
            options: options,
            key: public_key,
            comments: comments.trim_start().to_owned()
        })
    )
);

named!(
    pub(crate) parse_key_authorization<&str, KeyAuthorization>,
    alt_complete!(parse_optionless_key_authorization | parse_optioned_key_authorization)
);

#[cfg(test)]
mod tests {
    use super::super::super::models::{KeyType, PublicKey};
    use super::*;

    #[test]
    fn it_parses_full_authorizations() {
        let test_cases = &[
            (
                "ssh-ed25519 foobar==",
                KeyAuthorization {
                    options: KeyOptions::new(),
                    key: PublicKey {
                        key_type: KeyType::SshEd25519,
                        encoded_key: "foobar==".to_owned(),
                    },
                    comments: "".to_owned(),
                },
            ),
            (
                "restrict ecdsa-sha2-nistp521 istestbase64",
                KeyAuthorization {
                    options: vec![("restrict".to_owned(), None)],
                    key: PublicKey {
                        key_type: KeyType::EcdsaSha2Nistp521,
                        encoded_key: "istestbase64".to_owned(),
                    },
                    comments: "".to_owned(),
                },
            ),
            (
                "ssh-ed25519 foobar== now with comments",
                KeyAuthorization {
                    options: KeyOptions::new(),
                    key: PublicKey {
                        key_type: KeyType::SshEd25519,
                        encoded_key: "foobar==".to_owned(),
                    },
                    comments: "now with comments".to_owned(),
                },
            ),
            (
                "restrict ecdsa-sha2-nistp521 istestbase64 also with comments",
                KeyAuthorization {
                    options: vec![("restrict".to_owned(), None)],
                    key: PublicKey {
                        key_type: KeyType::EcdsaSha2Nistp521,
                        encoded_key: "istestbase64".to_owned(),
                    },
                    comments: "also with comments".to_owned(),
                },
            ),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_key_authorization(test_case);

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
