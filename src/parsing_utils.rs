use colored::Colorize;

use crate::context::Context;

pub fn parse_number(ctx: &Context, s: &str) -> Result<u64, std::num::ParseIntError> {
    let n;
    let base: &str;

    if let Some(stripped) = s.strip_prefix("0x") {
        base = "hexadecimal";
        n = u64::from_str_radix(stripped, 16);
    }
    else if let Some(stripped) = s.strip_prefix("0o") {
        base = "octal";
        n = u64::from_str_radix(stripped, 8);
    }
    else if let Some(stripped) = s.strip_prefix("0b") {
        base = "binary";
        n = u64::from_str_radix(stripped, 2);
    }
    else {
        base = "decimal";
        if let Some(stripped) = s.strip_prefix("-") {
            n = match u64::from_str_radix(stripped, 10) {
                Ok(v) => Ok(!v + 1),
                Err(e) => Err(e)
            }
        }
        else {
            n = u64::from_str_radix(s, 10);
        }
    }

    if n.is_err() {
        println!(
            "{} on line {}: invalid {} literal `{}`",
            "ArithmeticError".red(),
            ctx.line_no,
            base,
            s.yellow()
        );
    }
    n
}

pub fn test_number_8(n: i64) -> bool {
    n >= i8::MIN as i64 && n <= i8::MAX as i64
}

pub fn test_number_16(n: i64) -> bool {
    n >= i16::MIN as i64 && n <= i16::MAX as i64
}

pub fn test_number_32(n: i64) -> bool {
    n >= i32::MIN as i64 && n <= i32::MAX as i64
}
