use proc_macro::*;
use std::collections::HashMap;

fn get_reg_operands(input: TokenStream) -> (u32, u32, u32) {
    let reg_map = vec![
        ("t0", 5),
        ("t1", 6),
        ("t2", 7),
        ("t3", 28),
        ("t4", 29),
        ("t5", 30),
        ("t6", 31),
        ("a0", 10),
        ("a1", 11),
        ("a2", 12),
        ("a3", 13),
        ("s2", 18),
        ("s3", 19),
        ("s4", 20),
    ]
    .into_iter()
    .collect::<HashMap<_, u32>>();

    let ops = input
        .into_iter()
        .flat_map(|t| match t {
            TokenTree::Group(g) => g.stream(),
            x => TokenStream::from(x),
        })
        .filter(|t| matches!(t, TokenTree::Literal(_) | TokenTree::Ident(_)))
        .take(3)
        .map(|t| {
            let t = t.to_string();
            if let Ok(n) = t.parse::<u32>() {
                n
            } else if let Some(n) = reg_map.get(t.as_str()) {
                *n
            } else {
                println!("register: {}", t);
                panic!("unsupported register")
            }
        })
        .collect::<Vec<_>>();
    if ops.len() < 3 {
        panic!("too few operands");
    }
    (ops[0], ops[1], ops[2])
}

fn bin_5(x: u32) -> String {
    format!("{:05b}", x)
}

fn bin_11(x: u32) -> String {
    format!("{:011b}", x)
}

fn encode_hex(binstr: &str) -> String {
    let x = u32::from_str_radix(binstr, 2).unwrap();
    format!("{:#X}", x)
}

#[proc_macro]
pub fn ror(input: TokenStream) -> TokenStream {
    let (rd, rs1, rs2) = get_reg_operands(input);
    let hex = encode_hex(
        &[
            "0000100",
            &bin_5(rs2),
            &bin_5(rs1),
            "101",
            &bin_5(rd),
            "0110011",
        ]
        .join(""),
    );
    let res = format!(".4byte {}", hex);
    quote::quote! { #res }.into()
}

#[proc_macro]
pub fn add(input: TokenStream) -> TokenStream {
    let (rd, rs1, rs2) = get_reg_operands(input);
    let res = format!("add x{}, x{}, x{}", rd, rs1, rs2);
    quote::quote! { #res }.into()
}

#[proc_macro]
pub fn xor(input: TokenStream) -> TokenStream {
    let (rd, rs1, rs2) = get_reg_operands(input);
    let res = format!("xor x{}, x{}, x{}", rd, rs1, rs2);
    quote::quote! { #res }.into()
}

#[proc_macro]
pub fn lw_pi(input: TokenStream) -> TokenStream {
    let (rd, imm, rs1) = get_reg_operands(input);
    let hex = encode_hex(&[&bin_11(imm), &bin_5(rs1), "010", &bin_5(rd), "0001011"].join(""));
    let res = format!(".4byte {}", hex);
    quote::quote! { #res }.into()
}

#[proc_macro]
pub fn sw_pi(input: TokenStream) -> TokenStream {
    let (rs2, imm, rs1) = get_reg_operands(input);
    if imm > 4 {
        unimplemented!("unsupported offset");
    }
    let hex = encode_hex(
        &[
            "0000000",
            &bin_5(rs2),
            &bin_5(rs1),
            "010",
            &bin_5(imm),
            "0101011",
        ]
        .join(""),
    );
    let res = format!(".4byte {}", hex);
    quote::quote! { #res }.into()
}

#[proc_macro]
pub fn lp_setupi(input: TokenStream) -> TokenStream {
    let (l, uimms, uimml) = get_reg_operands(input);
    if l != 0 {
        unimplemented!("second loop not supported")
    }

    println!();
    let hex = encode_hex(&[&bin_11(uimml), &bin_5(uimms), "101", "0000", "0", "1111011"].join(""));
    let res = format!(".4byte {}", hex);
    quote::quote! { #res }.into()
}

#[proc_macro]
pub fn lp_setup(input: TokenStream) -> TokenStream {
    let (l, rs1, uimml) = get_reg_operands(input);
    if l != 0 {
        unimplemented!("second loop not supported")
    }

    println!();
    let hex = encode_hex(&[&bin_11(uimml), &bin_5(rs1), "100", "0000", "0", "1111011"].join(""));
    let res = format!(".4byte {}", hex);
    quote::quote! { #res }.into()
}
