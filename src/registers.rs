use std::collections::HashMap;
use lazy_static::lazy_static;

#[repr(u16)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum AsmRegister {
    AL,
    AH,
    BL,
    BH,
    CL,
    CH,
    DL,
    DH,
    AX,
    BX,
    CX,
    DX,
    SI,
    DI,
    SP,
    BP,
    EAX,
    EBX,
    ECX,
    EDX,
    ESI,
    EDI,
    ESP,
    EBP,
    CS,
    DS,
    ES,
    FS,
    GS,
    SS
}

lazy_static! {
    pub static ref REGISTERS: HashMap<&'static str, (AsmRegister, i32)> = HashMap::from([
        ("al", (AsmRegister::AL, 8)),
        ("ah", (AsmRegister::AH, 8)),
        ("bl", (AsmRegister::BL, 8)),
        ("bh", (AsmRegister::BH, 8)),
        ("cl", (AsmRegister::CL, 8)),
        ("ch", (AsmRegister::CH, 8)),
        ("dl", (AsmRegister::DL, 8)),
        ("dh", (AsmRegister::DH, 8)),
        ("ax", (AsmRegister::AX, 16)),
        ("bx", (AsmRegister::BX, 16)),
        ("cx", (AsmRegister::CX, 16)),
        ("dx", (AsmRegister::DX, 16)),
        ("si", (AsmRegister::SI, 16)),
        ("di", (AsmRegister::DI, 16)),
        ("sp", (AsmRegister::SP, 16)),
        ("bp", (AsmRegister::BP, 16)),
        ("eax", (AsmRegister::EAX, 32)),
        ("ebx", (AsmRegister::EBX, 32)),
        ("ecx", (AsmRegister::ECX, 32)),
        ("edx", (AsmRegister::EDX, 32)),
        ("esi", (AsmRegister::ESI, 32)),
        ("edi", (AsmRegister::EDI, 32)),
        ("esp", (AsmRegister::ESP, 32)),
        ("ebp", (AsmRegister::EBP, 32)),
        ("cs", (AsmRegister::CS, -1)),
        ("ds", (AsmRegister::DS, -1)),
        ("es", (AsmRegister::ES, -1)),
        ("fs", (AsmRegister::FS, -1)),
        ("gs", (AsmRegister::GS, -1)),
        ("ss", (AsmRegister::SS, -1))
    ]);

    pub static ref REGISTERS_ENCODING: HashMap<AsmRegister, u8> = HashMap::from([
        (AsmRegister::AL, 0b0000), (AsmRegister::AX, 0b0000), (AsmRegister::EAX, 0b0000),
        (AsmRegister::CL, 0b0001), (AsmRegister::CX, 0b0001), (AsmRegister::ECX, 0b0001),
        (AsmRegister::DL, 0b0010), (AsmRegister::DX, 0b0010), (AsmRegister::EDX, 0b0010),
        (AsmRegister::BL, 0b0011), (AsmRegister::BX, 0b0011), (AsmRegister::EBX, 0b0011),
        (AsmRegister::AH, 0b0100), (AsmRegister::SP, 0b0100), (AsmRegister::ESP, 0b0100),
        (AsmRegister::CH, 0b0101), (AsmRegister::BP, 0b0101), (AsmRegister::EBP, 0b0101),
        (AsmRegister::DH, 0b0110), (AsmRegister::SI, 0b0110), (AsmRegister::ESI, 0b0110),
        (AsmRegister::BH, 0b0111), (AsmRegister::DI, 0b0111), (AsmRegister::EDI, 0b0111),

        (AsmRegister::ES, 0b0000),
        (AsmRegister::CS, 0b0001),
        (AsmRegister::SS, 0b0010),
        (AsmRegister::DS, 0b0011),
        (AsmRegister::FS, 0b0100),
        (AsmRegister::GS, 0b0101)
    ]);
}