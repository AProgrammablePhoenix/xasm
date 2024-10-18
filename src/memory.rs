use std::num::Wrapping;
use colored::Colorize;

use crate::context::*;
use crate::parsing_utils::*;
use crate::registers::*;

#[derive(Copy, Clone)]
pub struct MemoryOperandDescriptor {
    // Legacy 16-bits fields

    size: u8,               // 16, 32 or 64
    bx: bool,               // true if BX is used
    bp: bool,               // true if BP is used
    si: bool,               // true if SI is used
    di: bool,               // true if DI is used
    disp: Wrapping<i64>,    // displacement

    // Legacy 32-bits fields

    index: u8,              // SIB-index
    scale: Wrapping<u8>,    // SIB-scale
    base: u8                // SIB-base
}

pub struct MemoryOperand {
    pub size        : u8,
    pub modrm       : u8,
    pub has_sib     : bool,
    pub sib         : u8,
    pub disp_size   : u8,
    pub disp        : u64
}

pub fn parse_memory(ctx: &mut Context, rs: &str) -> Result<MemoryOperandDescriptor, ()> {
    fn invalid_16_bit_repetition(ctx: &mut Context, atom: &str, rs: &str) -> Result<MemoryOperandDescriptor, ()> {
        println!(
            "{} on line {}: Illegal repetition of register `{}` in 16-bit address operand `[{}]`",
            "Error".red(),
            ctx.line_no,
            atom.yellow(),
            rs.purple()
        );
        ctx.on_error = true;
        Err(())
    }
    fn invalid_16_bit_combination(ctx: &mut Context, rs: &str) -> Result<MemoryOperandDescriptor, ()> {
        println!(
            "{} on line {}: Illegal combination of registers in 16-bit address operand `[{}]`",
            "Error".red(),
            ctx.line_no,
            rs.purple()
        );
        ctx.on_error = true;
        Err(())
    }    

    let s = rs.replace(" ", "");
    let mut atoms = Vec::new();
    let mut last = 0;
    for (i, m) in s.match_indices(['+', '-']) {
        if last != i {
            atoms.push(&s[last..i]);
        }
        atoms.push(m);
        last = i + m.len();
    }
    if last < s.len() {
        atoms.push(&s[last..]);
    }

    let mut desc = MemoryOperandDescriptor {
        size        : 0,
        bx          : false,
        bp          : false,
        si          : false,
        di          : false,
        disp        : Wrapping(0),
        index       : 0xFF,
        scale       : Wrapping(0),
        base        : 0xFF
    };

    let mut is_adding: bool = true;

    for atom in atoms {
        if atom == "+" {
            is_adding = true;
        }
        else if atom == "-" {
            is_adding = false;
        }
        else if REGISTERS.contains_key(atom) {
            let (reg, rsize) = REGISTERS[atom];
            match rsize {
                8 => {
                    println!(
                        "{} on line {}: Invalid memory operand `[{}]` (illegal use of 8-bit register `{}`)",
                        "Error".red(),
                        ctx.line_no,
                        rs.purple(),
                        atom.yellow()
                    );
                    ctx.on_error = true;
                    return Err(());
                },
                16 => {
                    if desc.size == 0 {
                        desc.size = 16;
                    } 
                    else if desc.size != 16 {
                        println!(
                            "{} on line {}: Invalid combination of 16-bit registers `{}` in {}-bit addressing memory operand `[{}]`",
                            "Error".red(),
                            ctx.line_no,
                            atom.yellow(),
                            desc.size,
                            rs.purple()
                        );
                        ctx.on_error = true;
                        return Err(());
                    }

                    macro_rules! match_16_bit_reg {
                        ($x:ident, $y:ident) => {{
                            if desc.$x {
                                return invalid_16_bit_repetition(ctx, atom, rs);
                            }
                            else if desc.$y {
                                return invalid_16_bit_combination(ctx, rs);
                            }
                            desc.$x = true;
                        }}
                    }

                    match reg {
                        AsmRegister::BX => match_16_bit_reg!(bx, bp),
                        AsmRegister::BP => match_16_bit_reg!(bp, bx),
                        AsmRegister::SI => match_16_bit_reg!(si, di),
                        AsmRegister::DI => match_16_bit_reg!(di, si),
                        _ => {
                            println!(
                                "{} on line {}: Use of invalid 16-bit register `{}` in 16-bit addressing memory operand `[{}]`",
                                "Error".red(),
                                ctx.line_no,
                                atom.yellow(),
                                rs.purple()
                            );
                            ctx.on_error = true;
                            return Err(());
                        }
                    }
                },
                32 => {
                    if desc.size == 0 {
                        desc.size = 32;
                    }
                    else if desc.size != 32 {
                        println!(
                            "{} on line {}: Invalid combination of 32-bit registers `{}` in {}-bit addressing memory operand `[{}]`",
                            "Error".red(),
                            ctx.line_no,
                            atom.yellow(),
                            desc.size,
                            rs.purple()
                        );
                        ctx.on_error = true;
                        return Err(());
                    }

                    let encoding = REGISTERS_ENCODING[&reg];

                    if desc.base ==  0xFF {
                        desc.base = encoding;
                    }
                    else if desc.index == 0xFF {
                        desc.scale = Wrapping(1);
                        desc.index = encoding;
                    }
                    else {
                        if encoding == desc.base {
                            if desc.index == 0xFF || desc.scale.0 == 1 {
                                desc.base = desc.index;
                                desc.index = encoding;
                                desc.scale = Wrapping(2);
                            }
                            else {
                                println!(
                                    "{} on line {}: Invalid repetition of 32-bit register `{}` in memory operand `[{}]`, consider using the format `[{}]`",
                                    "Error".red(),
                                    ctx.line_no,
                                    atom.yellow(),
                                    rs.purple(),
                                    "SCALE * INDEX + BASE + DISP".cyan()
                                );
                                ctx.on_error = true;
                                return Err(());
                            }
                        }
                        else if encoding == desc.index {
                            if is_adding {
                                desc.scale += 1;
                            }
                            else {
                                desc.scale -= 1;
                            }
                        }
                        else {
                            println!(
                                "{} on line {}: Invalid use of third 32-bit register `{}` in memory operand `[{}]`, consider using the format `[{}]`",
                                "Error".red(),
                                ctx.line_no,
                                atom.yellow(),
                                rs.purple(),
                                "SCALE * INDEX + BASE + DISP".cyan()
                            );
                            ctx.on_error = true;
                            return Err(());
                        }
                    }
                }
                _ => {
                    println!(
                        "{} on line {}: Unsupported width for {}-bit register `{}` in memory operand `[{}]`",
                        "Error".red(),
                        ctx.line_no,
                        if rsize == -1 {16} else { rsize },
                        atom.yellow(),
                        rs.purple()
                    );
                    ctx.on_error = true;
                    return Err(());
                }
            }
        }
        else if atom.contains('*') {
            let quarks: Vec<_> = atom.split('*').collect();

            let register_encoding: u8;
            let scale: u8;

            macro_rules! parse_quark {
                ($x:literal, $y:literal) => {
                    let (register, rsize) = REGISTERS[quarks[$x]];
                    if rsize != 32 {
                        println!(
                            "{} on line {}: Invalid width for register `{}` in scaled index `{}` in memory operand `[{}]`",
                            "Error".red(),
                            ctx.line_no,
                            quarks[$x].yellow(),
                            atom.purple(),
                            rs.purple()
                        );
                        ctx.on_error;
                        return Err(());
                    }

                    register_encoding = REGISTERS_ENCODING[&register];
                    match parse_number(ctx, quarks[$y]) {
                        Ok(v) if v == 1 || v == 2  || v == 4 || v == 8 => scale = v as u8,
                        _ => {
                            println!(
                                "{} on line {}: Invalid scale `{}` in memory operand `[{}]`, must be 1, 2, 4 or 8 ; default is 1 if absent",
                                "Error".red(),
                                ctx.line_no,
                                quarks[$y].yellow(),
                                rs.purple()
                            );
                            ctx.on_error = true;
                            return Err(());
                        }
                    }
                }
            }

            if quarks.len() != 2 {
                println!(
                    "{} on line {}: Too many fields in scaled index `{}` in memory operand `[{}]`, consider using the format `[{}]`",
                    "Error".red(),
                    ctx.line_no,
                    atom.yellow(),
                    rs.purple(),
                    "SCALE * INDEX + BASE + DISP".cyan()
                );
                ctx.on_error = true;
                return Err(());
            }
            else if REGISTERS.contains_key(quarks[0]) {
                parse_quark!(0, 1);
            }
            else if REGISTERS.contains_key(quarks[1]) {
                parse_quark!(1, 0);
            }
            else {
                println!(
                    "{} on line {}: Invalid scaled index `{}` in memory operand `[{}]`, no operand is a valid register",
                    "Error".red(),
                    ctx.line_no,
                    atom.yellow(),
                    rs.purple()
                );
                ctx.on_error = true;
                return Err(());
            }
            
            let mut wrapped_scale = Wrapping(scale);
            if !is_adding {
                wrapped_scale = -wrapped_scale;
            }
            
            if desc.index != 0xFF {
                if desc.index == register_encoding {
                    desc.scale += wrapped_scale;
                }
                else if desc.base == 0xFF && desc.scale.0 == 1 {
                    desc.base = desc.index;
                    desc.scale = wrapped_scale;
                }
                else {
                    println!(
                        "{} on line {}: Cannot have two scaled indexes in memory operand `[{}]`, consider using the format `[{}]`",
                        "Error".red(),
                        ctx.line_no,
                        rs.yellow(),
                        "SCALE * INDEX + BASE + DISP".cyan()
                    );
                    ctx.on_error = true;
                    return Err(());
                }
            }
            else if desc.base == register_encoding {
                desc.base = 0xFF;
                desc.scale = wrapped_scale;
            }
            else {
                desc.scale = wrapped_scale;
            }
            
            desc.index = register_encoding;
        }
        else {
            match parse_number(ctx, atom) {
                Ok(uv) => {
                    let mut sv = uv as i64;
                    if !test_number_32(sv) {
                        sv = (sv as i32) as i64;
                        println!(
                            "{} on line {}: Displacement magnitude of `{}` is too large, applying modulo 2^32, might cause unwanted or undefined behavior",
                            "Warning".yellow(),
                            ctx.line_no,
                            atom.yellow()
                        );
                    }
                    if is_adding {
                        desc.disp += sv;
                    }
                    else {
                        desc.disp -= sv;
                    }
                },
                _ => {
                    println!(
                        "{} on line {}: Invalid expression `{}` in memory operand `[{}]`, consider using the format `[{}]`",
                        "Error".red(),
                        ctx.line_no,
                        atom.yellow(),
                        rs.purple(),
                        "SCALE * INDEX + BASE + DISP".cyan()
                    );
                    ctx.on_error = true;
                    return Err(());
                }
            }
        }
    }

    return match desc.scale.0 {
        0 | 1 | 2 | 4 | 8 => Ok(desc),
        _ => {
            println!(
                "{} on line {}: Invalid scale `{}` in memory operand `[{}]`, valid values are 1, 2, 4 and 8.",
                "Error".red(),
                ctx.line_no,
                desc.scale.0.to_string().yellow(),
                rs.purple()
            );
            ctx.on_error = true;
            Err(())
        }
    };
}

pub fn build_modrm_core(rm: u8, reg: u8, _mod: u8) -> u8 {
    ((_mod & 0x3) << 6) | ((reg & 0x7) << 3) | (rm & 0x7)
}

pub fn make_modrm_sib(ctx: &mut Context, mut desc: MemoryOperandDescriptor, reg_v: u8) -> Result<MemoryOperand, ()> {
    macro_rules! build_16bit_modrm {
        ($rm:expr, $reg:expr) => {
            if desc.disp.0 == 0 {
                return Ok(MemoryOperand{
                    size        : 16,
                    modrm       : build_modrm_core($rm, $reg, 0b00),
                    has_sib     : false,
                    sib         : 0,
                    disp_size   : 0,
                    disp        : 0
                });
            }
            else if test_number_8(desc.disp.0) {
                return Ok(MemoryOperand{
                    size        : 16,
                    modrm       : build_modrm_core($rm, $reg, 0b01),
                    has_sib     : false,
                    sib         : 0,
                    disp_size   : 8,
                    disp        : desc.disp.0 as u64
                });
            }
            else if test_number_16(desc.disp.0) {
                return Ok(MemoryOperand{
                    size        : 16,
                    modrm       : build_modrm_core($rm, $reg, 0b10),
                    has_sib     : false,
                    sib         : 0,
                    disp_size   : 16,
                    disp        : desc.disp.0 as u64
                });
            }
            else {
                println!(
                    "{} on line {}: Displacement `{}` is too large for 16-bits addressing mode",
                    "Error".red(),
                    ctx.line_no,
                    desc.disp.0
                );
                return Err(());
            }
        }
    }

    macro_rules! build_sib_core {
        ($base:expr, $index:expr, $scale:expr) => {
            ((match $scale {
                2 => 0b01,
                4 => 0b10,
                8 => 0b11,
                _ => 0b00
            } << 6) | (($index & 0x7) << 3) | ($base & 0x7))
        }
    }
    
    match desc.size {
        16 => {
            if desc.bx {
                if desc.si {
                    build_16bit_modrm!(0b000, reg_v);
                }
                else if desc.di {
                    build_16bit_modrm!(0b001, reg_v);
                }
                else {
                    build_16bit_modrm!(0b111, reg_v);
                }
            }
            else if desc.bp {
                if desc.si {
                    build_16bit_modrm!(0b010, reg_v);
                }
                else if desc.di {
                    build_16bit_modrm!(0b011, reg_v);
                }
                else {
                    if test_number_8(desc.disp.0) {
                        return Ok(MemoryOperand{
                            size        : 16,
                            modrm       : build_modrm_core(0b110, reg_v, 0b01),
                            has_sib     : false,
                            sib         : 0,
                            disp_size   : 8,
                            disp        : desc.disp.0 as u64
                        });
                    }
                    else {
                        return Ok(MemoryOperand{
                            size        : 16,
                            modrm       : build_modrm_core(0b110, reg_v, 0b10),
                            has_sib     : false,
                            sib         : 0,
                            disp_size   : 16,
                            disp        : desc.disp.0 as u64
                        });
                    }
                }
            }
            else if desc.si {
                build_16bit_modrm!(0b100, reg_v);
            }
            else if desc.di {
                build_16bit_modrm!(0b101, reg_v);
            }
            else {
                return Ok(MemoryOperand{
                    size        : 16,
                    modrm       : build_modrm_core(0b110, reg_v, 0b00),
                    has_sib     : false,
                    sib         : 0,
                    disp_size   : 16,
                    disp        : desc.disp.0 as u64
                });
            }
        },
        32 => {
            let esp_encoding = REGISTERS_ENCODING[&AsmRegister::ESP];
            let ebp_encoding = REGISTERS_ENCODING[&AsmRegister::EBP];

            if desc.index == esp_encoding {
                if desc.scale.0 != 1 {
                    println!(
                        "{} on line {}: Cannot use ESP as a memory index",
                        "Error".red(),
                        ctx.line_no
                    );
                    ctx.on_error = true;
                    return Err(());
                }
                (desc.index, desc.base) = (desc.base, desc.index);
            }

            if desc.index == 0xFF && desc.base != esp_encoding {
                if desc.disp.0 == 0 {
                    if desc.base != ebp_encoding {
                        return Ok(MemoryOperand{
                            size        : 32,
                            modrm       : build_modrm_core(desc.base, reg_v, 0b00),
                            has_sib     : false,
                            sib         : 0,
                            disp_size   : 0,
                            disp        : 0
                        });
                    }
                }
                else if test_number_8(desc.disp.0) {
                    return Ok(MemoryOperand{
                        size        : 32,
                        modrm       : build_modrm_core(desc.base, reg_v, 0b01),
                        has_sib     : false,
                        sib         : 0,
                        disp_size   : 8,
                        disp        : desc.disp.0 as u64
                    });
                }
                else {
                    return Ok(MemoryOperand{
                        size        : 32,
                        modrm       : build_modrm_core(desc.base, reg_v, 0b10),
                        has_sib     : false,
                        sib         : 0,
                        disp_size   : 32,
                        disp        : desc.disp.0 as u64
                    });
                }
            }
            
            let sib_rm = esp_encoding;

            let disp_size = if test_number_8(desc.disp.0) { 8 } else { 32 };
            let mmod = if disp_size == 8 { 0b01 } else { 0b10 };

            if desc.base == 0xFF && desc.index == 0xFF {
                return Ok(MemoryOperand{
                    size        : 32,
                    modrm       : build_modrm_core(sib_rm, reg_v, 0b00),
                    has_sib     : true,
                    sib         : build_sib_core!(0b101, 0b100, 0b00),
                    disp_size   : 32,
                    disp        : desc.disp.0 as u64
                });
            }
            else if desc.base == ebp_encoding {
                if desc.index == 0xFF {
                    return Ok(MemoryOperand{
                        size        : 32,
                        modrm       : build_modrm_core(sib_rm, reg_v, mmod),
                        has_sib     : true,
                        sib         : build_sib_core!(ebp_encoding, esp_encoding, 0b00),
                        disp_size   : disp_size,
                        disp        : desc.disp.0 as u64
                    });
                }
                else {
                    return Ok(MemoryOperand{
                        size        : 32,
                        modrm       : build_modrm_core(sib_rm, reg_v, mmod),
                        has_sib     : true,
                        sib         : build_sib_core!(ebp_encoding, desc.index, desc.scale.0),
                        disp_size   : disp_size,
                        disp        : desc.disp.0 as u64
                    });
                }
            }
            else {
                if desc.index == 0xFF {
                    if desc.disp.0 == 0 {
                        return Ok(MemoryOperand{
                            size        : 32,
                            modrm       : build_modrm_core(sib_rm, reg_v, 0b00),
                            has_sib     : true,
                            sib         : build_sib_core!(desc.base, esp_encoding, 0b00),
                            disp_size   : 0,
                            disp        : 0
                        });
                    }
                    else {
                        return Ok(MemoryOperand{
                            size        : 32,
                            modrm       : build_modrm_core(sib_rm, reg_v, mmod),
                            has_sib     : true,
                            sib         : build_sib_core!(desc.base, esp_encoding, 0b00),
                            disp_size   : disp_size,
                            disp        : desc.disp.0 as u64
                        });
                    }
                }
                else if desc.base == 0xFF {
                    return Ok(MemoryOperand{
                        size        : 32,
                        modrm       : build_modrm_core(sib_rm, reg_v, 0b00),
                        has_sib     : true,
                        sib         : build_sib_core!(ebp_encoding, desc.index, desc.scale.0),
                        disp_size   : 32,
                        disp        : desc.disp.0 as u64
                    });
                }
                else if desc.disp.0 == 0 {
                    return Ok(MemoryOperand{
                        size        : 32,
                        modrm       : build_modrm_core(sib_rm, reg_v, 0b00),
                        has_sib     : true,
                        sib         : build_sib_core!(desc.base, desc.index, desc.scale.0),
                        disp_size   : 0,
                        disp        : 0
                    });
                }
                else {
                    return Ok(MemoryOperand{
                        size        : 32,
                        modrm       : build_modrm_core(sib_rm, reg_v, mmod),
                        has_sib     : true,
                        sib         : build_sib_core!(desc.base, desc.index, desc.scale.0),
                        disp_size   : disp_size,
                        disp        : desc.disp.0 as u64
                    });
                }
            }
        },
        _ => {
            return Err(());
        }
    }
}

pub fn output_disp_16(ctx: &mut Context, disp_size: u8, disp: u64) {
    match disp_size {
        8 => output_write(ctx, &(disp as u8).to_le_bytes()),
        16 => output_write(ctx, &(disp as u16).to_le_bytes()),
        _ => ()
    };
}

pub fn output_disp_32(ctx: &mut Context, disp_size: u8, disp: u64) {
    match disp_size {
        8 => output_write(ctx, &(disp as u8).to_le_bytes()),
        32 => output_write(ctx, &(disp as u32).to_le_bytes()),
        _ => ()
    }
}
