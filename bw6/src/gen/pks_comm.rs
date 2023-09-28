use super::super::keyset::KeysetCommitment;
use super::Bw6G1;
use serde::Serialize;
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct PksComm {
    pks_comm0: Bw6G1,
    pks_comm1: Bw6G1,
}

static PKS_COMM_TEMPLATE: &str = "
            pks_comm: [
                Bw6G1(\\{
                    x: Bw6Fp(\\{
                        a: {pks_comm0.x.a}
                        b: {pks_comm0.x.b},
                        c: {pks_comm0.x.c}
                    }),
                    y: Bw6Fp(\\{
                        a: {pks_comm0.y.a}
                        b: {pks_comm0.y.b},
                        c: {pks_comm0.y.c}
                    })
                }),
                Bw6G1(\\{
                    x: Bw6Fp(\\{
                        a: {pks_comm1.x.a}
                        b: {pks_comm1.x.b},
                        c: {pks_comm0.x.c}
                    }),
                    y: Bw6Fp(\\{
                        a: {pks_comm1.y.a}
                        b: {pks_comm1.y.b},
                        c: {pks_comm1.y.c}
                    })
                })
            ],
";

pub fn print_pks_comm(ks_comm: KeysetCommitment) {
    let mut tt = TinyTemplate::new();
    tt.add_template("pks_comm", PKS_COMM_TEMPLATE).unwrap();

    let pks_comm = ks_comm.pks_comm;

    let context = PksComm {
        pks_comm0: Bw6G1::from(pks_comm.0),
        pks_comm1: Bw6G1::from(pks_comm.1),
    };

    let rendered = tt.render("pks_comm", &context).unwrap();
    println!("{}", rendered);
}
