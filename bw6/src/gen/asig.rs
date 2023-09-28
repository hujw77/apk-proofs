use super::super::bls::Signature;
use ark_ec::CurveGroup;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use serde::Serialize;
use serde_hex::{SerHexSeq, StrictPfx};
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct AggregateSignature {
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_x_c0: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_x_c0: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_x_c1: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_x_c1: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_y_c0: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_y_c0: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_y_c1: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_y_c1: Vec<u8>,
}

static ASIG_TEMPLATE: &str = "
    function build_aggregate_signature() public pure returns (Bls12G2 memory) \\{
        return Bls12G2(
            Bls12Fp2(
                Bls12Fp(
					{h_x_c0}, {l_x_c0}
                ),
                Bls12Fp(
					{h_x_c1}, {l_x_c1}
                )
            ),
            Bls12Fp2(
                Bls12Fp(
					{h_y_c0}, {l_y_c0}
                ),
                Bls12Fp(
					{h_y_c1}, {l_y_c1}
                )
            )
        );
    }
";

pub fn print_asig(asig: Signature) {
    let mut tt = TinyTemplate::new();
    tt.add_template("asig", ASIG_TEMPLATE).unwrap();

    let sig = asig.as_ref().into_affine();
    let x_c0 = sig.x.c0.into_bigint().to_bytes_be();
    let (h_x_c0, l_x_c0) = x_c0.split_at(x_c0.len() - 32);

    let x_c1 = sig.x.c1.into_bigint().to_bytes_be();
    let (h_x_c1, l_x_c1) = x_c1.split_at(x_c1.len() - 32);

    let y_c0 = sig.y.c0.into_bigint().to_bytes_be();
    let (h_y_c0, l_y_c0) = y_c0.split_at(y_c0.len() - 32);

    let y_c1 = sig.y.c1.into_bigint().to_bytes_be();
    let (h_y_c1, l_y_c1) = y_c1.split_at(y_c1.len() - 32);

    let context = AggregateSignature {
        h_x_c0: h_x_c0.to_vec(),
        l_x_c0: l_x_c0.to_vec(),
        h_x_c1: h_x_c1.to_vec(),
        l_x_c1: l_x_c1.to_vec(),
        h_y_c0: h_y_c0.to_vec(),
        l_y_c0: l_y_c0.to_vec(),
        h_y_c1: h_y_c1.to_vec(),
        l_y_c1: l_y_c1.to_vec(),
    };

    let rendered = tt.render("asig", &context).unwrap();
    println!("{}", rendered);
}
