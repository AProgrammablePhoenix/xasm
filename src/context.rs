use std::fs::File;
use std::io::prelude::*;

use colored::Colorize;

pub enum BitsMode {
    M16,
    M32,
    M64
}

pub struct Context {
    pub b_mode      :   BitsMode,
    pub line_no     :   u64,
    pub output_file :   File,
    pub on_error    :   bool    
}

pub fn output_write(ctx: &mut Context, buffer: &[u8]) {
    if ctx.output_file.write(buffer).is_err() {
        panic!("{}: {}", "Abort".bright_red().bold(), "Could not write to output file".red());
    }
}

pub fn change_bits_mode(ctx: &mut Context, value: &str) {
    match value.parse::<u32>().unwrap_or_else(|_| {
        println!(
            "{} on line {}: invalid mode for BITS directive (accepted widths are 16, 32 and 64)",
            "Syntax error".red(),
            ctx.line_no
        );
        ctx.on_error = true;
        0
    }) {
        16 => ctx.b_mode = BitsMode::M16,
        32 => ctx.b_mode = BitsMode::M32,
        64 => ctx.b_mode = BitsMode::M64,
        _ => {
            println!(
                "{} on line {}: invalind mode for BITS directive (accepted widths are 16, 32 and 64)",
                "Error".red(),
                ctx. line_no
            );
            ctx.on_error = true;
        }
    }
}