use ark_bw6_761::Fr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_poly::Radix2EvaluationDomain;
use serde::Serialize;
use serde_hex::{SerHexSeq, StrictPfx};
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct Domain {
    size: u64,
    log_size_of_group: u32,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_size_inv: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_size_inv: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_group_gen: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_group_gen: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_group_gen_inv: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_group_gen_inv: Vec<u8>,
}

static DOMAIN_TEMPLATE: &str = "
    uint32 internal constant LOG_N = {log_size_of_group};

    function init() public pure returns (Radix2EvaluationDomain memory) \\{
        return Radix2EvaluationDomain(\\{
            size: {size},
            log_size_of_group: {log_size_of_group},
            size_as_field_element: Bw6Fr(0, {size}),
            size_inv: Bw6Fr(
				{h_size_inv}, {l_size_inv}
                ),
            group_gen: Bw6Fr(
				{h_group_gen}, {l_group_gen}
                ),
            group_gen_inv: Bw6Fr(
				{h_group_gen_inv}, {l_group_gen_inv}
                ),
            offset: BW6FR.one(),
            offset_inv: BW6FR.one(),
            offset_pow_size: BW6FR.one()
        });
    }
";

pub fn print_domain(domain: Radix2EvaluationDomain<Fr>) {
    let mut tt = TinyTemplate::new();
    tt.add_template("domain", DOMAIN_TEMPLATE).unwrap();

    let size_inv = domain.size_inv.into_bigint().to_bytes_be();
    let (h_size_inv, l_size_inv) = size_inv.split_at(size_inv.len() - 32);

    let group_gen = domain.group_gen.into_bigint().to_bytes_be();
    let (h_group_gen, l_group_gen) = group_gen.split_at(group_gen.len() - 32);

    let group_gen_inv = domain.group_gen_inv.into_bigint().to_bytes_be();
    let (h_group_gen_inv, l_group_gen_inv) = group_gen_inv.split_at(group_gen_inv.len() - 32);
    let context = Domain {
        size: domain.size,
        log_size_of_group: domain.log_size_of_group,
        h_size_inv: h_size_inv.to_vec(),
        l_size_inv: l_size_inv.to_vec(),
        h_group_gen: h_group_gen.to_vec(),
        l_group_gen: l_group_gen.to_vec(),
        h_group_gen_inv: h_group_gen_inv.to_vec(),
        l_group_gen_inv: l_group_gen_inv.to_vec(),
    };

    let rendered = tt.render("domain", &context).unwrap();
    println!("{}", rendered);
}
