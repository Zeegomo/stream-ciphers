use proc_macro::*;

fn get_reg_operands(input: TokenStream) -> (u8, u8, u8) {
    let ops = input.into_iter()
        .flat_map(|t| 
            match t {
                TokenTree::Group(g) => g.stream(),
                x => TokenStream::from(x),
        })
        .filter(|t| matches!(t, TokenTree::Literal(_)))
        .take(3)
        .map(|t| t.to_string().parse::<u8>().unwrap())
        .collect::<Vec<_>>();
    
    (ops[0], ops[1], ops[2])
}

fn bin_5(x: u8) -> String {
    format!("{:05b}", x)
}

fn bin_11(x: u8) -> String {
    format!("{:011b}", x)
}

fn encode_hex(binstr: &str) -> String {
    let x = u32::from_str_radix(binstr, 2).unwrap();
    format!("{:#X}", x)
}

#[proc_macro]
pub fn ror(input: TokenStream) -> TokenStream {
    let (rd, rs1, rs2) = get_reg_operands(input);
    let hex = encode_hex(&["0000100", &bin_5(rs2), &bin_5(rs1), "101", &bin_5(rd), "0110011"].join(""));
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
    let (rs1, imm, rs2) = get_reg_operands(input);
    if imm > 4 {
        panic!("unsupported offset");
    }
    let hex = encode_hex(&["0000000", &bin_5(rs2), &bin_5(rs1), "010", &bin_5(imm), "0001011"].join(""));
    let res = format!(".4byte {}", hex);
    quote::quote! { #res }.into()
}

