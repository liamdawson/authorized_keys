use nom::rest_s;

named!(
    pub(crate) parse_dashed_ident<&str, &str>,
    // if incomplete, successfully reached end of input: take everything
    alt_complete!(take_while1!(|c: char| c.is_ascii_alphanumeric() || c == '-') | rest_s)
);

named!(
    pub(crate) parse_escapable_string<&str, &str>,
    delimited!(
        char!('"'),
        // allow escaped quotes and backslashes, and take everything
        // that isn't an unescaped quote, or a linefeed
        escaped!(is_not!("\"\\"), '\\', one_of!("\"\\")),
        char!('"')
    )
);

named!(
    pub(crate) parse_line_remainder<&str, &str>,
    alt_complete!(is_not!("\r\n") | call!(nom::rest_s))
);

named!(
    pub(crate) parse_base64<&str, &str>,
    // if incomplete, successfully reached end of input: take everything
    alt_complete!(take_while1!(|c:char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') | rest_s)
);

named!(
    pub(crate) parse_whitespace<&str, &str>,
    take_while!(|c| c == ' ' || c == '\t')
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_dashed_idents_that_reach_eoi() {
        assert_eq!(
            parse_dashed_ident("test-value").unwrap(),
            ("", "test-value")
        );
    }

    #[test]
    fn it_parses_dashed_idents() {
        let test_cases = &["test", "hello-world", "ssh-ed25519"];

        for expected in test_cases {
            let res = parse_dashed_ident(&expected);

            assert!(
                res.is_ok(),
                "case '{}' failed: {}",
                expected,
                res.unwrap_err()
            );

            if let Ok((_, actual)) = res {
                assert_eq!(actual, *expected);
            }
        }
    }

    #[test]
    fn it_parses_escapable_strings() {
        let test_cases = &[
            (r#""""#, ""),
            (r#""uptime""#, "uptime"),
            (r#""echo \"Hello, world!\"""#, r#"echo \"Hello, world!\""#),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_escapable_string(test_case);

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
    fn it_parses_base64() {
        let test_cases = &["foobar==", "FullerRangeOfCharacters+/1==", "lesspadding="];

        for expected in test_cases {
            let res = parse_base64(&expected);

            assert!(
                res.is_ok(),
                "case '{}' failed: {}",
                expected,
                res.unwrap_err()
            );

            if let Ok((_, actual)) = res {
                assert_eq!(actual, *expected);
            }
        }
    }

    #[test]
    fn it_parses_line_remainder() {
        let test_cases = &[
            ("", ""),
            ("Hello, world!", "Hello, world!"),
            ("Windows newline test\r\n", "Windows newline test"),
            ("Unix newline test\n", "Unix newline test"),
        ];

        for (test_case, expected) in test_cases {
            let res = parse_line_remainder(test_case);

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
