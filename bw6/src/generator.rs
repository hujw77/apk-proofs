use ark_bw6_761::{Fr, BW6_761};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_poly::Radix2EvaluationDomain;
use fflonk::pcs::kzg::params::RawKzgVerifierKey;
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

#[derive(Serialize)]
struct RVK {
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_g1_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_g1_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_g1_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_g1_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_g1_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_g1_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_g2_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_g2_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_g2_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_g2_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_g2_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_g2_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_g2_tau_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_g2_tau_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_g2_tau_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_g2_tau_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_g2_tau_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_g2_tau_y: Vec<u8>,
}
static RVK_TEMPLATE: &str = "
    function raw_vk() public pure returns (RVK memory) \\{
        return RVK(\\{
            g1: Bw6G1(\\{
                x: Bw6Fp(\\{
                    a: {h_g1_x},
                    b: {m_g1_x},
                    c: {l_g1_x}
                }),
                y: Bw6Fp(\\{
                    a: {h_g1_y},
                    b: {m_g1_y},
                    c: {l_g1_y}
                })
            }),
            g2: Bw6G2(\\{
                x: Bw6Fp(\\{
                    a: {h_g2_x}
                    b: {m_g2_x},
                    c: {l_g2_x}
                }),
                y: Bw6Fp(\\{
                    a: {h_g2_y}
                    b: {m_g2_y},
                    c: {l_g2_y}
                })
            }),
            tau_in_g2: Bw6G2(\\{
                x: Bw6Fp(\\{
                    a: {h_g2_tau_x}
                    b: {m_g2_tau_x},
                    c: {l_g2_tau_x}
                }),
                y: Bw6Fp(\\{
                    a: {h_g2_tau_y}
                    b: {m_g2_tau_y},
                    c: {l_g2_tau_y}
                })
            })
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

pub fn print_rvk(rvk: RawKzgVerifierKey<BW6_761>) {
    let mut tt = TinyTemplate::new();
    tt.add_template("rvk", RVK_TEMPLATE).unwrap();

    let g1 = rvk.g1;
    let g1_x = g1.x.into_bigint().to_bytes_be();
    let (r_g1_x, l_g1_x) = g1_x.split_at(g1_x.len() - 32);
    let (h_g1_x, m_g1_x) = r_g1_x.split_at(r_g1_x.len() - 32);

    let g1_y = g1.y.into_bigint().to_bytes_be();
    let (r_g1_y, l_g1_y) = g1_y.split_at(g1_y.len() - 32);
    let (h_g1_y, m_g1_y) = r_g1_y.split_at(r_g1_y.len() - 32);

    let g2 = rvk.g2;
    let g2_x = g2.x.into_bigint().to_bytes_be();
    let (r_g2_x, l_g2_x) = g2_x.split_at(g2_x.len() - 32);
    let (h_g2_x, m_g2_x) = r_g2_x.split_at(r_g2_x.len() - 32);

    let g2_y = g2.y.into_bigint().to_bytes_be();
    let (r_g2_y, l_g2_y) = g2_y.split_at(g2_y.len() - 32);
    let (h_g2_y, m_g2_y) = r_g2_y.split_at(r_g2_y.len() - 32);

    let g2_tau = rvk.tau_in_g2;
    let g2_tau_x = g2_tau.x.into_bigint().to_bytes_be();
    let (r_g2_tau_x, l_g2_tau_x) = g2_tau_x.split_at(g2_tau_x.len() - 32);
    let (h_g2_tau_x, m_g2_tau_x) = r_g2_tau_x.split_at(r_g2_tau_x.len() - 32);

    let g2_tau_y = g2_tau.y.into_bigint().to_bytes_be();
    let (r_g2_tau_y, l_g2_tau_y) = g2_tau_y.split_at(g2_tau_y.len() - 32);
    let (h_g2_tau_y, m_g2_tau_y) = r_g2_tau_y.split_at(r_g2_tau_y.len() - 32);

    let context = RVK {
        h_g1_x: h_g1_x.to_vec(),
        m_g1_x: m_g1_x.to_vec(),
        l_g1_x: l_g1_x.to_vec(),
        h_g1_y: h_g1_y.to_vec(),
        m_g1_y: m_g1_y.to_vec(),
        l_g1_y: l_g1_y.to_vec(),
        h_g2_x: h_g2_x.to_vec(),
        m_g2_x: m_g2_x.to_vec(),
        l_g2_x: l_g2_x.to_vec(),
        h_g2_y: h_g2_y.to_vec(),
        m_g2_y: m_g2_y.to_vec(),
        l_g2_y: l_g2_y.to_vec(),
        h_g2_tau_x: h_g2_tau_x.to_vec(),
        m_g2_tau_x: m_g2_tau_x.to_vec(),
        l_g2_tau_x: l_g2_tau_x.to_vec(),
        h_g2_tau_y: h_g2_tau_y.to_vec(),
        m_g2_tau_y: m_g2_tau_y.to_vec(),
        l_g2_tau_y: l_g2_tau_y.to_vec(),
    };

    let rendered = tt.render("rvk", &context).unwrap();
    println!("{}", rendered);
}
