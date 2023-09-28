use super::super::AccountablePublicInput;
use ark_ff::PrimeField;
use ark_ff::{BigInteger, BigInteger256};
use serde::Serialize;
use serde_hex::{SerHexSeq, StrictPfx};
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct PublicInput {
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_apk_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_apk_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_apk_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_apk_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    bitmask: Vec<u8>,
    padding_size: usize,
}

static PUBLIC_INPUT_TEMPLATE: &str = "
    function build_public_input() public pure returns (AccountablePublicInput memory) \\{
        uint256[] memory limbs = new uint[](1);
        limbs[0] = {bitmask};
        AccountablePublicInput memory public_input = AccountablePublicInput(\\{
            apk: Bls12G1(\\{
                x: Bls12Fp(\\{
                    a: {h_apk_x},
                    b: {l_apk_x}
                }),
                y: Bls12Fp(\\{
                    a: {h_apk_y},
                    b: {l_apk_y}
                })
            }),
            bitmask: Bitmask(\\{limbs: limbs, padding_size: {padding_size}})
        });
        return public_input;
    }
";

pub fn print_public_input(public_input: &AccountablePublicInput) {
    let mut tt = TinyTemplate::new();
    tt.add_template("public_input", PUBLIC_INPUT_TEMPLATE)
        .unwrap();

    let apk = public_input.apk;
    let apk_x = apk.x.into_bigint().to_bytes_be();
    let (h_apk_x, l_apk_x) = apk_x.split_at(apk_x.len() - 32);

    let apk_y = apk.y.into_bigint().to_bytes_be();
    let (h_apk_y, l_apk_y) = apk_y.split_at(apk_y.len() - 32);

    let bitmask = &public_input.bitmask;
    let bm = BigInteger256::from_bits_le(&bitmask.to_bits());

    let context = PublicInput {
        h_apk_x: h_apk_x.to_vec(),
        l_apk_x: l_apk_x.to_vec(),
        h_apk_y: h_apk_y.to_vec(),
        l_apk_y: l_apk_y.to_vec(),
        bitmask: bm.to_bytes_be(),
        padding_size: bitmask.padding_size,
    };

    let rendered = tt.render("public_input", &context).unwrap();
    println!("{}", rendered);
}
