use super::super::AccountablePublicInput;
use super::Bls12G1;
use ark_ff::{BigInteger, BigInteger256};
use serde::Serialize;
use serde_hex::{SerHexSeq, StrictPfx};
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct PublicInput {
    apk: Bls12G1,
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
                    a: {apk.x.a},
                    b: {apk.x.b}
                }),
                y: Bls12Fp(\\{
                    a: {apk.y.a},
                    b: {apk.y.b}
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

    let bitmask = &public_input.bitmask;
    let bm = BigInteger256::from_bits_le(&bitmask.to_bits());

    let context = PublicInput {
        apk: Bls12G1::from(apk),
        bitmask: bm.to_bytes_be(),
        padding_size: bitmask.padding_size,
    };

    let rendered = tt.render("public_input", &context).unwrap();
    println!("{}", rendered);
}
