use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};

use colored::Colorize;
use lazy_static::lazy_static;

mod context;
mod instructions;
mod memory;
mod registers;
mod parsing_utils;

use context::*;
use instructions::*;
use memory::*;
use registers::*;
use parsing_utils::*;

enum AsmArg {
    Immediate(u64),
    Register(AsmRegister, i32),
    Memory(MemoryOperandDescriptor, u8)
}

fn expect_arguments<const N: usize>(ctx: &mut Context, s: &str) -> Option<Vec<AsmArg>> {
    let trimmed = s.trim();
    let (raw_args, _) = trimmed.split_once(";").unwrap_or((trimmed, ""));
    let args: Vec<_> = raw_args.split(',').collect();

    if args.len() != N {
        return None;
    }

    let mut parsed_args = Vec::<AsmArg>::new();
    
    for arg in args {
        let mut trimmed_arg = arg.trim();
        let size_override: u8;

        if let Some(stripped) = trimmed_arg.strip_prefix("%byte") {
            size_override = 8;
            trimmed_arg = stripped.trim();
        }
        else if let Some(stripped) = trimmed_arg.strip_prefix("%word") {
            size_override = 16;
            trimmed_arg = stripped.trim();
        }
        else if let Some(stripped) = trimmed_arg.strip_prefix("%dword") {
            size_override = 32;
            trimmed_arg = stripped.trim();
        }
        else if let Some(stripped) = trimmed_arg.strip_prefix("%qword") {
            size_override = 64;
            trimmed_arg = stripped.trim();
        }
        else {
            size_override = 0;
        }

        if REGISTERS.contains_key(trimmed_arg) {
            let (r, s) = REGISTERS[trimmed_arg];
            parsed_args.push(AsmArg::Register(r, s));
        }
        else if let Some(stripped) = trimmed_arg.strip_prefix('[') {
            let mut chars = stripped.chars();
            chars.next_back();
            match parse_memory(ctx, chars.as_str()) {
                Ok(mem_desc) => parsed_args.push(AsmArg::Memory(mem_desc, size_override)),
                _ => {
                    println!(
                        "{} on line {}: Invalid memory operand detected for `{}`",
                        "Error".red(),
                        ctx.line_no,
                        trimmed_arg
                    );
                    ctx.on_error = true;
                    return None;
                }
            }
        }
        else if let Ok(parsed_number) = parse_number(ctx, trimmed_arg) {
            parsed_args.push(AsmArg::Immediate(parsed_number as u64));
        }
        else {
            println!(
                "{} on line {}: Invalid argument format for `{}`",
                "Error".red(),
                ctx.line_no,
                trimmed_arg
            );
            ctx.on_error = true;
            return None;
        }
    }

    if parsed_args.len() != N {
        return None;
    }

    Some(parsed_args)
}

fn aaa(ctx: &mut Context, args: &str) {
    let trimmed = args.trim();

    if !trimmed.is_empty() && !args.trim().starts_with(";") {
        println!(
            "{} on line {}: unexpected instruction arguments `{}`",
            "Error".red(),
            ctx.line_no,
            args.yellow()
        );
        ctx.on_error = true;
    }
    else {
        output_write(ctx, &[0x37]);
    }
}

fn aad(ctx: &mut Context, args: &str) {
    let trimmed = args.trim();
    let (arg, _) = trimmed.split_once(";").unwrap_or((trimmed, ""));
    
    if trimmed.is_empty() || arg.is_empty() {
        output_write(ctx, &[0xD5, 0x0A]);
    }
    else {
        let parsed = parse_number(ctx, arg).unwrap_or_else(|_| {
            println!(
                "{} on line {}: invalid argument provided to `{}`: `{}`",
                "Error".red(),
                ctx.line_no,
                "aad".purple(),
                arg.yellow()
            );
            ctx.on_error = true;
            0
        }) as u8;
        output_write(ctx, &[0xD5, parsed]);
    }
}

fn aam(ctx: &mut Context, args: &str) {
    let trimmed = args.trim();
    let (arg, _) = trimmed.split_once(";").unwrap_or((trimmed, ""));

    if trimmed.is_empty() || arg.is_empty() {
        output_write(ctx, &[0xD4, 0x0A]);
    }
    else {
        let parsed = parse_number(ctx, arg).unwrap_or_else(|_| {
            println!(
                "{} on line {}: invalid argument provided to `{}`: `{}`",
                "Error".red(),
                ctx.line_no,
                "aam".purple(),
                arg.yellow()
            );
            ctx.on_error = true;
            0
        }) as u8;
        output_write(ctx, &[0xD4, parsed]);
    }
}

fn aas(ctx: &mut Context, args: &str) {
    let trimmed = args.trim();

    if !trimmed.is_empty() && !trimmed.starts_with(";") {
        println!(
            "{} on line {}: unexpected instruction arguments `{}`",
            "Error".red(),
            ctx.line_no,
            args.yellow()
        );
        ctx.on_error = true;
    }
    else {
        output_write(ctx, &[0x3F]);
    }
}

fn pure_alu<const OP_A_8_IMM: u8, const OP_RM_R_8: u8, const OP_MI_MODRM_REGV: u8>(ctx: &mut Context, args: &str, instr: &'static str) {
    let op_a_def_imm      : u8 = OP_A_8_IMM + 1;
    let op_r_8_imm        : u8 = 0x80;
    let op_r_def_imm      : u8 = 0x81;
    let op_r_def_imm_8    : u8 = 0x83;
    let op_rm_r_def       : u8 = OP_RM_R_8 + 1;
    let op_r_rm_8         : u8 = OP_RM_R_8 + 2;
    let op_r_rm_def       : u8 = OP_RM_R_8 + 3;

    let parsed_args = expect_arguments::<2>(ctx, args).unwrap_or_else(|| {
        println!(
            "{} on line {}: Invalid number of arguments for `{}`: `{}`",
            "Error".red(),
            ctx.line_no,
            instr.purple(),
            args.yellow()
        );
        ctx.on_error = true;
        Vec::new()
    });
    if ctx.on_error {
        return;
    }

    if let AsmArg::Immediate(imm) = parsed_args[1] {
        if let AsmArg::Register(r0, s0) = parsed_args[0] {
            if !x86_format_i(ctx, &FormatI {
                register    : r0,
                imm         : imm,
                op_imm8     : OP_A_8_IMM,
                op_imm_def  : op_a_def_imm
            }) {
                x86_format_ri(ctx, instr, &FormatRI {
                    register        : r0,
                    register_size   : s0,
                    imm             : imm,
                    default_reg_v   : OP_MI_MODRM_REGV,
                    r8_imm8_op      : op_r_8_imm,
                    r_def_imm8_op   : op_r_def_imm_8,
                    r_imm_def_op    : op_r_def_imm
                });
            }
        }
        else if let AsmArg::Memory(mdesc, size_override) = parsed_args[0] {
            return x86_format_mi(ctx, &FormatMI {
                mdesc           : mdesc,
                size_override   : size_override,
                imm             : imm,
                default_reg_v   : OP_MI_MODRM_REGV,
                r8_imm8_op      : op_r_8_imm,
                r_imm_def_op    : op_r_def_imm,
                r_def_imm8_op   : op_r_def_imm_8
            });
        }
        else {
            println!(
                "{} on line {}: Wrong destination operand type for `{}`, expected a register or memory operand",
                "Error".red(),
                ctx.line_no,
                instr.yellow()
            );
            ctx.on_error = true;
            return;
        }
    }
    else if let AsmArg::Register(rs, ss) = parsed_args[1] {
        if let AsmArg::Register(rd, sd) = parsed_args[0] {
            return x86_format_rr(ctx, instr, &FormatRR {
                reg_source      : rs,
                reg_source_size : ss,
                reg_dest        : rd,
                reg_dest_size   : sd,
                r8_op           : OP_RM_R_8,
                r_def_op        : op_rm_r_def
            });
        }
        else if let AsmArg::Memory(mdesc, size_override) = parsed_args[0] {
            return x86_format_mr(ctx, &FormatMR {
                mdesc           : mdesc,
                size_override   : size_override,
                reg_size        : ss,
                default_reg_v   : REGISTERS_ENCODING[&rs],
                r8_rm8_op       : OP_RM_R_8,
                r_rm_def_op     : op_rm_r_def,
                prefixes        : &[],
                ex_prefixes     : &[]
            });
        }
        else {
            println!(
                "{} on line {}: Wrong destination operand type for `{}`, expected a register or memory operand",
                "Error".red(),
                ctx.line_no,
                instr.yellow()
            );
            ctx.on_error = true;
            return;
        }
    }
    else if let AsmArg::Memory(mdesc, size_override) = parsed_args[1] {
        if let AsmArg::Register(rd, sd) = parsed_args[0] {
            return x86_format_mr(ctx, &FormatMR {
                mdesc           : mdesc,
                size_override   : size_override,
                reg_size        : sd,
                default_reg_v   : REGISTERS_ENCODING[&rd],
                r8_rm8_op       : op_r_rm_8,
                r_rm_def_op     : op_r_rm_def,
                prefixes        : &[],
                ex_prefixes     : &[]
            });
        }
        else {
            println!(
                "{} on line {}: Wrong destination operand type for `{}`, expected a register operand",
                "Error".red(),
                ctx.line_no,
                instr.yellow()
            );
            ctx.on_error = true;
            return;
        }
    }
}

fn adc(ctx: &mut Context, args: &str) {
    pure_alu::<0x14, 0x10, 0x2>(ctx, args, "adc");
}

fn adcx(ctx: &mut Context, args: &str) {
    fn print_size_error(ctx: &mut Context) {
        println!(
            "{} on line {}: `{}` requires the use of a 32-bit destination register and a 32-bit register/memory source",
            "Error".red(),
            ctx.line_no,
            "adcx".yellow()
        );
        ctx.on_error = true;
    }

    let parsed_args = expect_arguments::<2>(ctx, args).unwrap_or_else(|| {
        println!(
            "{} on line {}: Invalid number of arguments for `{}`: `{}`",
            "Error".red(),
            ctx.line_no,
            "adcx".purple(),
            args.yellow()
        );
        ctx.on_error = true;
        Vec::new()
    });
    if ctx.on_error {
        return;
    }

    if let AsmArg::Register(rd, sd) = parsed_args[0] {
        if sd != 32 {
            return print_size_error(ctx);
        }

        if let AsmArg::Register(rs, ss) = parsed_args[1] {
            if ss != 32 {
                return print_size_error(ctx);
            }
            
            output_write(ctx, &[0x66, 0x0F, 0x38, 0xF6]);
            output_write(ctx, &[build_modrm_core(REGISTERS_ENCODING[&rs], REGISTERS_ENCODING[&rd], 0b11)]);
        }
        else if let AsmArg::Memory(mdesc, size_override) = parsed_args[1] {
            return x86_format_mr(ctx, &FormatMR{
                mdesc           : mdesc,
                size_override   : size_override,
                reg_size        : sd,
                default_reg_v   : REGISTERS_ENCODING[&rd],
                r8_rm8_op       : 0xF6,
                r_rm_def_op     : 0xF6,
                prefixes        : &[0x66, 0x0F, 0x38, 0xF6],
                ex_prefixes     : &[0x66]
            });
        }
        else {
            println!(
                "{} on line {}: Invalid operands for `{}`, expected `{}`",
                "Error".red(),
                ctx.line_no,
                "adox".purple(),
                "adcx r32, r/m32".yellow()
            );
        }
    }
    else {
        println!(
            "{} on line {}: Invalid operands for `{}`, expected `{}`",
            "Error".red(),
            ctx.line_no,
            "adcx".purple(),
            "adox r32, r/m32".yellow()
        );
    }
}

fn add(ctx: &mut Context, args: &str) {
    pure_alu::<0x04, 0x00, 0x0>(ctx, args, "add");
}

fn adox(ctx: &mut Context, args: &str) {
    fn print_size_error(ctx: &mut Context) {
        println!(
            "{} on line {}: `{}` requires the use of a 32-bit destination register and a 32-bit register/memory source",
            "Error".red(),
            ctx.line_no,
            "adox".yellow()
        );
        ctx.on_error = true;
    }

    let parsed_args = expect_arguments::<2>(ctx, args).unwrap_or_else(|| {
        println!(
            "{} on line {}: Invalid number of arguments for `{}`: `{}`",
            "Error".red(),
            ctx.line_no,
            "adox".purple(),
            args.yellow()
        );
        ctx.on_error = true;
        Vec::new()
    });
    if ctx.on_error {
        return;
    }

    if let AsmArg::Register(rd, sd) = parsed_args[0] {
        if sd != 32 {
            return print_size_error(ctx);
        }

        if let AsmArg::Register(rs, ss) = parsed_args[1] {
            if ss != 32 {
                return print_size_error(ctx);
            }

            output_write(ctx, &[0xF3, 0x0F, 0x38, 0xF6]);
            output_write(ctx, &[build_modrm_core(REGISTERS_ENCODING[&rs], REGISTERS_ENCODING[&rd], 0b11)]);
        }
        else if let AsmArg::Memory(mdesc, size_override) = parsed_args[1] {
            return x86_format_mr(ctx, &FormatMR {
                mdesc           : mdesc,
                size_override   : size_override,
                reg_size        : sd,
                default_reg_v   : REGISTERS_ENCODING[&rd],
                r8_rm8_op       : 0xF6,
                r_rm_def_op     : 0xF6,
                prefixes        : &[0xF3, 0x0F, 0x38, 0xF6],
                ex_prefixes     : &[0xF3, 0x66]
            });
        }
        else {
            println!(
                "{} on line {}: Invalid operands for `{}`, expected `{}`",
                "Error".red(),
                ctx.line_no,
                "adox".purple(),
                "adox r32, r/m32".yellow()
            );
        }
    }
    else {
        println!(
            "{} on line {}: Invalid operands for `{}`, expected `{}`",
            "Error".red(),
            ctx.line_no,
            "adox".purple(),
            "adox r32, r/m32".yellow()
        );
    }
}

fn and(ctx: &mut Context, args: &str) {
    pure_alu::<0x24, 0x20, 0x4>(ctx, args, "and");
}

fn arpl(ctx: &mut Context, args: &str) {
    fn print_size_error(ctx: &mut Context) {
        println!(
            "{} on line {}: `{}` requires the use of a 16-bit source register and a 16-bit register/memory destination",
            "Error".red(),
            ctx.line_no,
            "arpl".yellow()
        );
        ctx.on_error = true;
    }

    let parsed_args = expect_arguments::<2>(ctx, args).unwrap_or_else(|| {
        println!(
            "{} on line {}: Invalid number of arguments for `{}`: `{}`",
            "Error".red(),
            ctx.line_no,
            "arpl".purple(),
            args.yellow()
        );
        ctx.on_error = true;
        Vec::new()
    });
    if ctx.on_error {
        return;
    }

    if let AsmArg::Register(rs, ss) = parsed_args[1] {
        if ss != 16 {
            return print_size_error(ctx);
        }

        if let AsmArg::Register(rd, sd) = parsed_args[0] {
            if sd != 16 {
                return print_size_error(ctx);
            }

            output_write(ctx, &[0x63]);
            output_write(ctx, &[build_modrm_core(REGISTERS_ENCODING[&rd], REGISTERS_ENCODING[&rs], 0b11)]);
        }
        else if let AsmArg::Memory(mdesc, size_override) = parsed_args[0] {
            return x86_format_mr(ctx, &FormatMR {
                mdesc           : mdesc,
                size_override   : size_override,
                reg_size        : ss,
                default_reg_v   : REGISTERS_ENCODING[&rs],
                r8_rm8_op       : 0x63,
                r_rm_def_op     : 0x63,
                prefixes        : &[],
                ex_prefixes     : &[0x66]
            });
        }
        else {
            println!(
                "{} on line {}: Invalid operands for `{}`, expected `{}`",
                "Error".red(),
                ctx.line_no,
                "arpl".purple(),
                "arpl r/m16, r16".yellow()
            );
        }
    }
    else {
        println!(
            "{} on line {}: Invalid operands for `{}`, expected `{}`",
            "Error".red(),
            ctx.line_no,
            "arpl".purple(),
            "arpl r/m16, r16".yellow()
        );
    }
}

fn bound(ctx: &mut Context, args: &str) {
    let parsed_args = expect_arguments::<2>(ctx, args).unwrap_or_else(|| {
        println!(
            "{} on line {}: Invalid number of arguments for `{}`: `{}`",
            "Error".red(),
            ctx.line_no,
            "bound".purple(),
            args.yellow()
        );
        ctx.on_error = true;
        Vec::new()
    });
    if ctx.on_error {
        return;
    }

    if let AsmArg::Register(rd, sd) = parsed_args[0] {
        if let AsmArg::Memory(mdesc, size_override) = parsed_args[1] {
            if (size_override != 0 && size_override != 16 && size_override != 32) || (sd != 16 && sd != 32) {
                println!(
                    "{} on line {}: Invalid operands for `{}`, expected `{}`",
                    "Error".red(),
                    ctx.line_no,
                    "bound".purple(),
                    "bound r16, m16&16 | bound r32, m32&m32".yellow()
                );
                ctx.on_error = true;
                return;
            }

            return x86_format_mr(ctx, &FormatMR {
                mdesc               : mdesc,
                size_override       : size_override,
                reg_size            : sd,
                default_reg_v       : REGISTERS_ENCODING[&rd],
                r8_rm8_op           : 0x62,
                r_rm_def_op         : 0x62,
                prefixes            : &[],
                ex_prefixes         : &[]
            });
        }
        else {
            println!(
                "{} on line {}: Invalid operands for `{}`, expected `{}`",
                "Error".red(),
                ctx.line_no,
                "bound".purple(),
                "bound r16, m16&16 | bound r32, m32&m32".yellow()
            );
            ctx.on_error = true;
            return;
        }
    }
    else {
        println!(
            "{} on line {}: Invalid operands for `{}`, expected `{}`",
            "Error".red(),
            ctx.line_no,
            "bound".purple(),
            "bound r16, m16&16 | bound r32, m32&m32".yellow()
        );
        ctx.on_error = true;
        return;
    }
}

fn bsf(ctx: &mut Context, args: &str) {
    let parsed_args = expect_arguments::<2>(ctx, args).unwrap_or_else(|| {
        println!(
            "{} on line {}: Invalid number of arguments for `{}`: `{}`",
            "Error".red(),
            ctx.line_no,
            "bound".purple(),
            args.yellow()
        );
        ctx.on_error = true;
        Vec::new()
    });
    if ctx.on_error {
        return;
    }

    if let AsmArg::Register(rd, sd) = parsed_args[0] {
        if sd != 16 && sd != 32 {
            println!(
                "{} on line {}: Invalid operands for `{}`, expected `{}`",
                "Error".red(),
                ctx.line_no,
                "bsf".purple(),
                "bsf r16, r/m16 | bsf r32, r/m32".yellow()
            );
            ctx.on_error = true;
            return;
        }

        if let AsmArg::Register(rs, ss) = parsed_args[1] {
            return x86_format_rr(ctx, "bsf", &FormatRR {
                reg_source      : rs,
                reg_source_size : ss,
                reg_dest        : rd,
                reg_dest_size   : sd,
                r8_op           : 0xBC,
                r_def_op        : 0xBC
            });
        }
    }
    else {
        println!(
            "{} on line {}: Invalid operands for `{}`, expected `{}`",
            "Error".red(),
            ctx.line_no,
            "bsf".purple(),
            "bsf r16, r/m16 | bsf r32, r/m32".yellow()
        );
        ctx.on_error = true;
        return;
    }
}

lazy_static! {
    static ref INSTRUCTIONS: HashMap<&'static str, fn(&mut Context, &str)> = HashMap::from([
        ("aaa", aaa as fn(&mut Context, &str)),
        ("aad", aad as fn(&mut Context, &str)),
        ("aam", aam as fn(&mut Context, &str)),
        ("aas", aas as fn(&mut Context, &str)),
        ("adc", adc as fn(&mut Context, &str)),
        ("adcx", adcx as fn(&mut Context, &str)),
        ("add", add as fn(&mut Context, &str)),
        ("adox", adox as fn(&mut Context, &str)),
        ("and", and as fn(&mut Context, &str)),
        ("arpl", arpl as fn(&mut Context, &str)),
        ("bound", bound as fn(&mut Context, &str))
    ]);
}

fn assemble_line(ctx: &mut Context, line: &str) {
    if line.is_empty() || line.starts_with("//") || line.starts_with(";") || line.starts_with("#") {
        return;
    }
    else if let Some(stripped) = line.strip_prefix("bits ") {
        change_bits_mode(ctx, stripped);        
    }
    else if let Some(stripped) = line.strip_prefix("[bits ") {
        let mut chars = stripped.chars();
        chars.next_back();
        change_bits_mode(ctx, chars.as_str());
    }
    else {
        let (instruction, args) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        if !INSTRUCTIONS.contains_key(instruction) {
            println!(
                "{} on line {}: invalid instruction `{}`",
                "Error".red(),
                ctx.line_no,
                instruction.yellow()
            );
            ctx.on_error = true;
            return;
        }

        INSTRUCTIONS[instruction](ctx, args);
    }
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 2 {
        println!("Usage: xasm <input file> <output file>");
        return Ok(());
    }
    
    let input_file_path: String = args[0].clone();
    let output_file_path: String = args[1].clone();

    let input_file = File::open(input_file_path)?;
    let reader = BufReader::new(input_file);

    let mut ctx = Context {
        b_mode      : BitsMode::M16,
        line_no     : 1,
        output_file : File::create(output_file_path)?,
        on_error    : false
    };
    
    for line in reader.lines() {
        let normalized = line?.trim().to_lowercase();
        assemble_line(&mut ctx, normalized.as_str());
        ctx.line_no += 1;
    }

    if ctx.on_error {
        println!("{}", "Generation failed, output file may contain invalid data".red());
        return Ok(());
    }

    Ok(())
}
