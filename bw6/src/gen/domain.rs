use super::Uint512;
use ark_bw6_761::Fr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_poly::Radix2EvaluationDomain;
use serde::Serialize;
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct Domain {
    size: u64,
    log_size_of_group: u32,
    size_inv: Uint512,
    group_gen: Uint512,
    group_gen_inv: Uint512,
}

static DOMAIN_TEMPLATE: &str = "
    uint32 internal constant LOG_N = {log_size_of_group};

    function init() public pure returns (Radix2EvaluationDomain memory) \\{
        return Radix2EvaluationDomain(\\{
            size: {size},
            log_size_of_group: {log_size_of_group},
            size_as_field_element: Bw6Fr(0, {size}),
            size_inv: Bw6Fr(
				{size_inv.a}, {size_inv.b}
                ),
            group_gen: Bw6Fr(
				{group_gen.a}, {group_gen.b}
                ),
            group_gen_inv: Bw6Fr(
				{group_gen_inv.a}, {group_gen_inv.b}
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
    let group_gen = domain.group_gen.into_bigint().to_bytes_be();
    let group_gen_inv = domain.group_gen_inv.into_bigint().to_bytes_be();

    let context = Domain {
        size: domain.size,
        log_size_of_group: domain.log_size_of_group,
        size_inv: Uint512::from(size_inv),
        group_gen: Uint512::from(group_gen),
        group_gen_inv: Uint512::from(group_gen_inv),
    };

    let rendered = tt.render("domain", &context).unwrap();
    println!("{}", rendered);
}
