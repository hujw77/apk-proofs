use super::super::keyset::KeysetCommitment;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use serde::Serialize;
use serde_hex::{SerHexSeq, StrictPfx};
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct PksComm {
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_pks_comm0_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_pks_comm0_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_pks_comm0_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_pks_comm0_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_pks_comm0_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_pks_comm0_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_pks_comm1_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_pks_comm1_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_pks_comm1_x: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    h_pks_comm1_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    m_pks_comm1_y: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    l_pks_comm1_y: Vec<u8>,
}

static PKS_COMM_TEMPLATE: &str = "
            pks_comm: [
                Bw6G1(\\{
                    x: Bw6Fp(\\{
                        a: {h_pks_comm0_x}
                        b: {m_pks_comm0_x},
                        c: {l_pks_comm0_x}
                    }),
                    y: Bw6Fp(\\{
                        a: {h_pks_comm1_y}
                        b: {m_pks_comm1_y},
                        c: {l_pks_comm1_y}
                    })
                }),
                Bw6G1(\\{
                    x: Bw6Fp(\\{
                        a: {h_pks_comm1_x}
                        b: {m_pks_comm1_x},
                        c: {l_pks_comm1_x}
                    }),
                    y: Bw6Fp(\\{
                        a: {h_pks_comm1_y}
                        b: {m_pks_comm1_y},
                        c: {l_pks_comm1_y}
                    })
                })
            ],
";

pub fn print_pks_comm(ks_comm: KeysetCommitment) {
    let mut tt = TinyTemplate::new();
    tt.add_template("pks_comm", PKS_COMM_TEMPLATE).unwrap();

    let pks_comm0 = ks_comm.pks_comm.0;
    let pks_comm0_x = pks_comm0.x.into_bigint().to_bytes_be();
    let (r_pks_comm0_x, l_pks_comm0_x) = pks_comm0_x.split_at(pks_comm0_x.len() - 32);
    let (h_pks_comm0_x, m_pks_comm0_x) = r_pks_comm0_x.split_at(r_pks_comm0_x.len() - 32);

    let pks_comm0_y = pks_comm0.y.into_bigint().to_bytes_be();
    let (r_pks_comm0_y, l_pks_comm0_y) = pks_comm0_y.split_at(pks_comm0_y.len() - 32);
    let (h_pks_comm0_y, m_pks_comm0_y) = r_pks_comm0_y.split_at(r_pks_comm0_y.len() - 32);

    let pks_comm1 = ks_comm.pks_comm.1;
    let pks_comm1_x = pks_comm1.x.into_bigint().to_bytes_be();
    let (r_pks_comm1_x, l_pks_comm1_x) = pks_comm1_x.split_at(pks_comm1_x.len() - 32);
    let (h_pks_comm1_x, m_pks_comm1_x) = r_pks_comm1_x.split_at(r_pks_comm1_x.len() - 32);

    let pks_comm1_y = pks_comm1.y.into_bigint().to_bytes_be();
    let (r_pks_comm1_y, l_pks_comm1_y) = pks_comm1_y.split_at(pks_comm1_y.len() - 32);
    let (h_pks_comm1_y, m_pks_comm1_y) = r_pks_comm1_y.split_at(r_pks_comm1_y.len() - 32);

    let context = PksComm {
        h_pks_comm0_x: h_pks_comm0_x.to_vec(),
        m_pks_comm0_x: m_pks_comm0_x.to_vec(),
        l_pks_comm0_x: l_pks_comm0_x.to_vec(),
        h_pks_comm0_y: h_pks_comm0_y.to_vec(),
        m_pks_comm0_y: m_pks_comm0_y.to_vec(),
        l_pks_comm0_y: l_pks_comm0_y.to_vec(),
        h_pks_comm1_x: h_pks_comm1_x.to_vec(),
        m_pks_comm1_x: m_pks_comm1_x.to_vec(),
        l_pks_comm1_x: l_pks_comm1_x.to_vec(),
        h_pks_comm1_y: h_pks_comm1_y.to_vec(),
        m_pks_comm1_y: m_pks_comm1_y.to_vec(),
        l_pks_comm1_y: l_pks_comm1_y.to_vec(),
    };

    let rendered = tt.render("pks_comm", &context).unwrap();
    println!("{}", rendered);
}
