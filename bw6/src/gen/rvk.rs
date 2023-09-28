use super::{Bw6G1, Bw6G2};
use ark_bw6_761::BW6_761;
use fflonk::pcs::kzg::params::RawKzgVerifierKey;
use serde::Serialize;
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct Rvk {
    g1: Bw6G1,
    g2: Bw6G2,
    tau_in_g2: Bw6G2,
}

static RVK_TEMPLATE: &str = "
    function raw_vk() public pure returns (RVK memory) \\{
        return RVK(\\{
            g1: Bw6G1(\\{
                x: Bw6Fp(\\{
                    a: {g1.x.a},
                    b: {g1.x.b},
                    c: {g1.x.c}
                }),
                y: Bw6Fp(\\{
                    a: {g1.y.a},
                    b: {g1.y.b},
                    c: {g1.y.c}
                })
            }),
            g2: Bw6G2(\\{
                x: Bw6Fp(\\{
                    a: {g2.x.a}
                    b: {g2.x.b},
                    c: {g2.x.c}
                }),
                y: Bw6Fp(\\{
                    a: {g2.y.a}
                    b: {g2.y.b},
                    c: {g2.y.c}
                })
            }),
            tau_in_g2: Bw6G2(\\{
                x: Bw6Fp(\\{
                    a: {tau_in_g2.x.a}
                    b: {tau_in_g2.x.b},
                    c: {tau_in_g2.x.c}
                }),
                y: Bw6Fp(\\{
                    a: {tau_in_g2.y.a}
                    b: {tau_in_g2.y.b},
                    c: {tau_in_g2.y.c}
                })
            })
        });
    }
";

pub fn print_rvk(rvk: RawKzgVerifierKey<BW6_761>) {
    let mut tt = TinyTemplate::new();
    tt.add_template("rvk", RVK_TEMPLATE).unwrap();

    let context = Rvk {
        g1: Bw6G1::from(rvk.g1),
        g2: Bw6G2::from(rvk.g2),
        tau_in_g2: Bw6G2::from(rvk.tau_in_g2),
    };

    let rendered = tt.render("rvk", &context).unwrap();
    println!("{}", rendered);
}
