use colored::Colorize;

use crate::context::*;
use crate::memory::*;
use crate::parsing_utils::*;

pub struct FormatMI {
    pub mdesc           : MemoryOperandDescriptor,
    pub size_override   : u8,
    pub imm             : u64,

    pub default_reg_v   : u8,
    pub r8_imm8_op      : u8,
    pub r_imm_def_op    : u8,
    pub r_def_imm8_op   : u8
}

pub struct FormatMR {
    pub mdesc           : MemoryOperandDescriptor,
    pub size_override   : u8,
    pub reg_size        : i32,

    pub default_reg_v   : u8,
    pub r8_rm8_op       : u8,
    pub r_rm_def_op     : u8
}

pub fn x86_format_mi(ctx: &mut Context, fparams: &FormatMI) {
    let imm = fparams.imm;
    let size_override = fparams.size_override;

    fn print_size_warning<const SIZE: usize>(ctx: &Context, imm: u64) {
        if SIZE == 8 {
            if !test_number_8(imm as i64) {
                println!(
                    "{} on line {}: Immediate value too large to fit in 8 bits, truncating to 8 bits",
                    "Warning".yellow(),
                    ctx.line_no
                );
            }
        }
        else if SIZE == 16 {
            if !test_number_16(imm as i64) {
                println!(
                    "{} on line {}: Immediate value too large to fit in 16 bits, truncating to 16 bits",
                    "Warning".yellow(),
                    ctx.line_no
                );
            }
        }
        else if SIZE == 32 {
            if !test_number_32(imm as i64) {
                println!(
                    "{} on line {}: Immediate value too large to fit in 32 bits, truncating to 32 bits",
                    "Warning".yellow(),
                    ctx.line_no
                );
            }
        }
    }

    fn generate<const IMM_SIZE: usize, const DISP_MODE: u8>(ctx: &mut Context, prefixes: &[u8], op: u8, mmop: &MemoryOperand, imm: u64) {
        output_write(ctx, prefixes);
        output_write(ctx, &[op, mmop.modrm]);

        if mmop.has_sib {
            output_write(ctx, &[mmop.sib]);
        }

        if DISP_MODE == 16 {
            output_disp_16(ctx, mmop.disp_size, mmop.disp);
        }
        else {
            output_disp_32(ctx, mmop.disp_size, mmop.disp);
        }

        match IMM_SIZE {
            8 => output_write(ctx, &[imm as u8]),
            16 => output_write(ctx, &(imm as u16).to_le_bytes()),
            32 => output_write(ctx, &(imm as u32).to_le_bytes()),
            _ => ()
        }
    }

    fn generate_warning<const IMM_SIZE: usize, const DISP_MODE: u8>(ctx: &mut Context, prefixes: &[u8], op: u8, mmop: &MemoryOperand, imm: u64) {
        if IMM_SIZE != 0 {
            print_size_warning::<IMM_SIZE>(ctx, imm);
        }
        generate::<IMM_SIZE, DISP_MODE>(ctx, prefixes, op, mmop, imm);
    }

    match make_modrm_sib(ctx, fparams.mdesc, fparams.default_reg_v) {
        Ok(mmop) => {
            match mmop.size {
                16 => {
                    if let BitsMode::M16 = ctx.b_mode {
                        if size_override == 8 {
                            generate_warning::<8, 16>(ctx, &[], fparams.r8_imm8_op, &mmop, imm);
                        }
                        else if size_override == 0 || size_override == 16 {
                            if test_number_8(imm as i64) {
                                generate::<8, 16>(ctx, &[], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate_warning::<16, 16>(ctx, &[], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else if size_override == 32 {
                            if test_number_8(imm as i64) {
                                generate::<8, 16>(ctx, &[0x66], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate_warning::<32, 16>(ctx, &[0x66], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else {
                            println!(
                                "{} on line {}: 64 bits addressing is unsupported in 16 bits mode",
                                "Error".red(),
                                ctx.line_no
                            );
                            ctx.on_error = true;
                            return;
                        }
                    }
                    else if let BitsMode::M32 = ctx.b_mode {
                        if size_override == 8 {
                            generate_warning::<8, 16>(ctx, &[0x67], fparams.r8_imm8_op, &mmop, imm);
                        }
                        else if size_override == 16 {
                            if test_number_8(imm as i64) {
                                generate::<8, 16>(ctx, &[0x66, 0x67], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate_warning::<16, 16>(ctx, &[0x67], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else if size_override == 0 || size_override == 32 {
                            if test_number_8(imm as i64) {
                                generate::<8, 16>(ctx, &[0x67], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate::<32, 16>(ctx, &[0x67], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else {
                            println!(
                                "{} on line {}: 64 bits addressing is unsupported in 32 bits mode",
                                "Error".red(),
                                ctx.line_no
                            );
                            ctx.on_error = true;
                            return;
                        }
                    }
                    else {
                        println!(
                            "{} on line {}: 64-bits instructions/operands are currently unsupported",
                            "Error".red(),
                            ctx.line_no                                    
                        );
                        ctx.on_error = true;
                        return;
                    }
                },
                32 => {
                    if let BitsMode::M16 = ctx.b_mode {
                        if size_override == 8 {
                            generate_warning::<8, 32>(ctx, &[0x67], fparams.r8_imm8_op, &mmop, imm);
                        }
                        else if size_override == 16 {
                            if test_number_8(imm as i64) {
                                generate::<8, 32>(ctx, &[0x67], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate_warning::<16, 32>(ctx, &[0x67], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else if size_override == 0 || size_override == 32 {
                            if test_number_8(imm as i64) {
                                generate::<8, 32>(ctx, &[0x66, 0x67], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate_warning::<32, 32>(ctx, &[0x66, 0x67], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else {
                            println!(
                                "{} on line {}: 64 bits addressing is unsupported in 16 bits mode",
                                "Error".red(),
                                ctx.line_no
                            );
                            ctx.on_error = true;
                            return;
                        }
                    }
                    else if let BitsMode::M32 = ctx.b_mode {
                        if size_override == 8 {
                            generate_warning::<8, 32>(ctx, &[], fparams.r8_imm8_op, &mmop, imm);
                        }
                        else if size_override == 16 {
                            if test_number_8(imm as i64) {
                                generate::<8, 32>(ctx, &[0x66], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate_warning::<16, 32>(ctx, &[0x66], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else if size_override == 0 || size_override == 32 {
                            if test_number_8(imm as i64) {
                                generate::<8, 32>(ctx, &[], fparams.r_def_imm8_op, &mmop, imm);
                            }
                            else {
                                generate_warning::<32, 32>(ctx, &[], fparams.r_imm_def_op, &mmop, imm);
                            }
                        }
                        else {
                            println!(
                                "{} on line {}: 64 bits addressing is unsupported in 32 bits mode",
                                "Error".red(),
                                ctx.line_no
                            );
                            ctx.on_error = true;
                            return;
                        }
                    }
                    else {
                        println!(
                            "{} on line {}: 64-bits instructions/operands are currently unsupported",
                            "Error".red(),
                            ctx.line_no                                    
                        );
                        ctx.on_error = true;
                        return;
                    }
                },
                _ => {
                    println!(
                        "{} on line {}: 64 bits addressing is unsupported",
                        "Error".red(),
                        ctx.line_no
                    );
                    ctx.on_error = true;
                    return;
                }
            }
        }
        _ => {
            println!(
                "{} on line {}: Invalid memory descriptor",
                "Error".red(),
                ctx.line_no
            );
            ctx.on_error = true;
            return;
        }
    }
}

pub fn x86_format_mr(ctx: &mut Context, fparams: &FormatMR) {
    fn generate<const DISP_MODE: u8>(ctx: &mut Context, prefixes: &[u8], op: u8, mmop: &MemoryOperand) {
        output_write(ctx, prefixes);
        output_write(ctx, &[op, mmop.modrm]);

        if mmop.has_sib {
            output_write(ctx, &[mmop.sib]);
        }

        if DISP_MODE == 16 {
            output_disp_16(ctx, mmop.disp_size, mmop.disp);
        }
        else {
            output_disp_32(ctx, mmop.disp_size, mmop.disp);
        }
    }

    match make_modrm_sib(ctx, fparams.mdesc, fparams.default_reg_v) {
        Ok(mmop) => {
            if fparams.size_override != 0 && (fparams.size_override as i32) != fparams.reg_size {
                println!(
                    "{} on line {}: Mismatched operand sizes",
                    "Error".red(),
                    ctx.line_no
                );
                ctx.on_error = true;
                return;
            }

            match mmop.size {
                16 => {
                    match ctx.b_mode {
                        BitsMode::M16 => {
                            match fparams.reg_size {
                                8 => generate::<16>(ctx, &[], fparams.r8_rm8_op, &mmop),
                                16 => generate::<16>(ctx, &[], fparams.r_rm_def_op, &mmop),
                                32 => generate::<16>(ctx, &[0x66], fparams.r_rm_def_op, &mmop),
                                _ => {
                                    println!(
                                        "{} on line {}: 64 bits registers use is unsupported in 16 bits mode",
                                        "Error".red(),
                                        ctx.line_no
                                    );
                                    ctx.on_error = true;
                                    return;
                                }
                            }
                        },
                        BitsMode::M32 => {
                            match fparams.reg_size {
                                8 => generate::<16>(ctx, &[0x67], fparams.r8_rm8_op, &mmop),
                                16 => generate::<16>(ctx, &[0x66, 0x67], fparams.r_rm_def_op, &mmop),
                                32 => generate::<16>(ctx, &[0x67], fparams.r_rm_def_op, &mmop),
                                _ => {
                                    println!(
                                        "{} on line {}: 64 bits registers use is unsupported in 32 bits mode",
                                        "Error".red(),
                                        ctx.line_no
                                    );
                                    ctx.on_error = true;
                                    return;
                                }
                            }
                        },
                        _ => {
                            println!(
                                "{} on line {}: 64-bits instructions/operands are currently unsupported",
                                "Error".red(),
                                ctx.line_no                                    
                            );
                            ctx.on_error = true;
                            return;
                        }
                    }
                },
                32 => {
                    match ctx.b_mode {
                        BitsMode::M16 => {
                            match fparams.reg_size {
                                8 => generate::<32>(ctx, &[0x67], fparams.r8_rm8_op, &mmop),
                                16 => generate::<32>(ctx, &[0x67], fparams.r_rm_def_op, &mmop),
                                32 => generate::<32>(ctx, &[0x66, 0x67], fparams.r_rm_def_op, &mmop),
                                _ => {
                                    println!(
                                        "{} on line {}: 64 bits registers use is unsupported in 16 bits mode",
                                        "Error".red(),
                                        ctx.line_no
                                    );
                                    ctx.on_error = true;
                                    return;
                                }
                            }
                        },
                        BitsMode::M32 => {
                            match fparams.reg_size {
                                8 => generate::<32>(ctx, &[], fparams.r8_rm8_op, &mmop),
                                16 => generate::<32>(ctx, &[0x66], fparams.r_rm_def_op, &mmop),
                                32 => generate::<32>(ctx, &[], fparams.r_rm_def_op, &mmop),
                                _ => {
                                    println!(
                                        "{} on line {}: 64 bits registers use is unsupported in 32 bits mode",
                                        "Error".red(),
                                        ctx.line_no
                                    );
                                    ctx.on_error = true;
                                    return;
                                }
                            }
                        },
                        _ => {
                            println!(
                                "{} on line {}: 64-bits instructions/operands are currently unsupported",
                                "Error".red(),
                                ctx.line_no                                    
                            );
                            ctx.on_error = true;
                            return;
                        }
                    }
                },
                _ => {
                    println!(
                        "{} on line {}: 64 bits addressing is unsupported",
                        "Error".red(),
                        ctx.line_no
                    );
                    ctx.on_error = true;
                    return;
                }
            }
        },
        _ => {
            println!(
                "{} on line {}: Invalid memory operand",
                "Error".red(),
                ctx.line_no
            );
            ctx.on_error = true;
            return;
        }
    }
}
