use crate::piop::RegisterEvaluations;

use super::super::SimpleProof;
use super::{Bw6G1, Uint512};
use serde::Serialize;
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct AEW {
    keyset: (Uint512, Uint512),
    partial_sums: (Uint512, Uint512),
}

#[derive(Serialize)]
struct SP {
    register_commitments: (Bw6G1, Bw6G1),
    q_comm: Bw6G1,
    register_evaluations: AEW,
    q_zeta: Uint512,
    r_zeta_omega: Uint512,
    w_at_zeta_proof: Bw6G1,
    r_at_zeta_omega_proof: Bw6G1,
}

static SIMPLE_PROOF_TEMPLATE: &str = "
    function build_proof() public pure returns (SimpleProof memory) \\{
        SimpleProof memory proof = SimpleProof(\\{
            register_commitments: [
                Bw6G1(\\{
                    x: Bw6Fp(\\{
                        a: {register_commitments.0.x.a},
                        b: {register_commitments.0.x.b},
                        c: {register_commitments.0.x.c}
                    }),
                    y: Bw6Fp(\\{
                        a: {register_commitments.0.y.a},
                        b: {register_commitments.0.y.b},
                        c: {register_commitments.0.y.c}
                    })
                }),
                Bw6G1(\\{
                    x: Bw6Fp(\\{
                        a: {register_commitments.1.x.a},
                        b: {register_commitments.1.x.b},
                        c: {register_commitments.1.x.c}
                    }),
                    y: Bw6Fp(\\{
                        a: {register_commitments.1.y.a},
                        b: {register_commitments.1.y.b},
                        c: {register_commitments.1.y.c}
                    })
                })
            ],
            q_comm: Bw6G1(\\{
                x: Bw6Fp(\\{
                    a: {q_comm.x.a},
                    b: {q_comm.x.b},
                    c: {q_comm.x.c}
                }),
                y: Bw6Fp(\\{
                    a: {q_comm.y.a}
                    b: {q_comm.y.b},
                    c: {q_comm.y.c}
                })
            }),
            register_evaluations: AffineAdditionEvaluationsWithoutBitmask(\\{
                keyset: [
                    Bw6Fr(\\{
                        a: {register_evaluations.keyset.0.a},
                        b: {register_evaluations.keyset.0.b}
                    }),
                    Bw6Fr(\\{
                        a: {register_evaluations.keyset.1.a},
                        b: {register_evaluations.keyset.1.b}
                    })
                ],
                partial_sums: [
                    Bw6Fr(\\{
                        a: {register_evaluations.partial_sums.0.a},
                        b: {register_evaluations.partial_sums.0.b}
                    }),
                    Bw6Fr(\\{
                        a: {register_evaluations.partial_sums.1.a},
                        b: {register_evaluations.partial_sums.1.b}
                    })
                ]
            }),
            q_zeta: Bw6Fr(\\{
                a: {q_zeta.a},
                b: {q_zeta.b}
            }),
            r_zeta_omega: Bw6Fr(\\{
                a: {r_zeta_omega.a},
                b: {r_zeta_omega.b}
            }),
            w_at_zeta_proof: Bw6G1(\\{
                x: Bw6Fp(\\{
                    a: {w_at_zeta_proof.x.a},
                    b: {w_at_zeta_proof.x.b},
                    c: {w_at_zeta_proof.x.c}
                }),
                y: Bw6Fp(\\{
                    a: {w_at_zeta_proof.y.a},
                    b: {w_at_zeta_proof.y.b},
                    c: {w_at_zeta_proof.y.c}
                })
            }),
            r_at_zeta_omega_proof: Bw6G1(\\{
                x: Bw6Fp(\\{
                    a: {r_at_zeta_omega_proof.x.a},
                    b: {r_at_zeta_omega_proof.x.b},
                    c: {r_at_zeta_omega_proof.x.c}
                }),
                y: Bw6Fp(\\{
                    a: {r_at_zeta_omega_proof.y.a},
                    b: {r_at_zeta_omega_proof.y.b},
                    c: {r_at_zeta_omega_proof.y.c}
                })
            })
        });
        return proof;
    }
";

pub fn print_simple_proof(simple_proof: &SimpleProof) {
    let mut tt = TinyTemplate::new();
    tt.add_template("simple_proof", SIMPLE_PROOF_TEMPLATE)
        .unwrap();

    let register_commitments = &simple_proof.register_commitments;
    let register_commitments0 = Bw6G1::from(register_commitments.0);
    let register_commitments1 = Bw6G1::from(register_commitments.1);
    let q_comm = Bw6G1::from(simple_proof.q_comm);
    let keyset0 = simple_proof.register_evaluations.keyset.0;
    let keyset1 = simple_proof.register_evaluations.keyset.1;
    let partial_sums0 = simple_proof.register_evaluations.partial_sums.0;
    let partial_sums1 = simple_proof.register_evaluations.partial_sums.1;
    let register_evaluations = AEW {
        keyset: (Uint512::from_fr(keyset0), Uint512::from_fr(keyset1)),
        partial_sums: (
            Uint512::from_fr(partial_sums0),
            Uint512::from_fr(partial_sums1),
        ),
    };

    let context = SP {
        register_commitments: (register_commitments0, register_commitments1),
        q_comm,
        register_evaluations,
        q_zeta: Uint512::from_fr(simple_proof.q_zeta),
        r_zeta_omega: Uint512::from_fr(simple_proof.r_zeta_omega),
        w_at_zeta_proof: Bw6G1::from(simple_proof.w_at_zeta_proof),
        r_at_zeta_omega_proof: Bw6G1::from(simple_proof.r_at_zeta_omega_proof),
    };

    let rendered = tt.render("simple_proof", &context).unwrap();
    println!("{}", rendered);
}
