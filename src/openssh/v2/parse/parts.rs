use super::atoms::*;

type RawKeyOption<'a> = (&'a str, Option<&'a str>);

named!(
    pub(crate) parse_option_with_value<&str, RawKeyOption>,
    separated_pair!(parse_dashed_ident, char!('='), map!(parse_escapable_string, Some))
);

named!(
    pub(crate) parse_option<&str, RawKeyOption>,
    alt_complete!(parse_option_with_value | map!(parse_dashed_ident, |v| (v, None)))
);

named!(
    pub(crate) parse_options<&str, Vec<RawKeyOption>>,
    separated_list_complete!(char!(','), parse_option)
);

named!(
    pub(crate) parse_public_key<&str, (&str, &str)>,
    separated_pair!(parse_dashed_ident, take_while!(|c| c == ' ' || c == '\t'), parse_base64)
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_options_with_value() {
        let test_cases = &[
            (r#"command="""#, ("command", Some(""))),
            (
                r#"agent-forwarding="echo \"Hello, world!\"""#,
                ("agent-forwarding", Some(r#"echo \"Hello, world!\""#)),
            ),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_option_with_value(test_case);

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
    fn it_parses_options() {
        let test_cases = &[
            ("restrict", ("restrict", None)),
            (r#"command="""#, ("command", Some(""))),
            (
                r#"agent-forwarding="echo \"Hello, world!\"""#,
                ("agent-forwarding", Some(r#"echo \"Hello, world!\""#)),
            ),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_option(test_case);

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
    fn it_parses_public_keys() {
        let test_cases = &[
            ("ssh-ed25519    foobar01 ", ("ssh-ed25519", "foobar01")),
            (
                "ecdsa-sha2-nistp256 \t testval= ",
                ("ecdsa-sha2-nistp256", "testval="),
            ),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_public_key(test_case);

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
    fn it_parses_multiple_options() {
        let test_cases = &[
            ("restrict", vec![("restrict", None)]),
            (
                r#"restrict,command="""#,
                vec![("restrict", None), ("command", Some(""))],
            ),
            (
                r#"restrict,fake-option="echo \"Hello, world!\"",and-finally"#,
                vec![
                    ("restrict", None),
                    ("fake-option", Some(r#"echo \"Hello, world!\""#)),
                    ("and-finally", None),
                ],
            ),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_options(test_case);

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
