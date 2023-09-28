use crate::piop::RegisterEvaluations;

use super::super::PackedProof;
use super::{Bw6G1, Uint512};
use serde::Serialize;
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct AE {
    keyset: (Uint512, Uint512),
    bitmask: Uint512,
    partial_sums: (Uint512, Uint512),
}

#[derive(Serialize)]
struct SARE {
    c: Uint512,
    acc: Uint512,
    basic_evaluations: AE,
}

#[derive(Serialize)]
struct PP {
    register_commitments: (Bw6G1, Bw6G1, Bw6G1),
    additional_commitments: (Bw6G1, Bw6G1),
    q_comm: Bw6G1,
    register_evaluations: SARE,
    q_zeta: Uint512,
    r_zeta_omega: Uint512,
    w_at_zeta_proof: Bw6G1,
    r_at_zeta_omega_proof: Bw6G1,
}

static SIMPLE_PROOF_TEMPLATE: &str = "
    function build_proof() public pure returns (PackedProof memory) \\{
        PackedProof memory proof = PackedProof(\\{
            register_commitments: PartialSumsAndBitmaskCommitments(\\{
                partial_sums: [
                    Bw6G1(
                        Bw6Fp(
							{register_commitments.0.x.a},
							{register_commitments.0.x.b},
							{register_commitments.0.x.c}
                        ),
                        Bw6Fp(
							{register_commitments.0.y.a},
							{register_commitments.0.y.b},
							{register_commitments.0.y.c}
                        )
                    ),
                    Bw6G1(
                        Bw6Fp(
							{register_commitments.1.x.a},
							{register_commitments.1.x.b},
							{register_commitments.1.x.c}
                        ),
                        Bw6Fp(
							{register_commitments.1.y.a},
							{register_commitments.1.y.b},
							{register_commitments.1.y.c}
                        )
                    )
                ],
                bitmask: Bw6G1(
                    Bw6Fp(
						{register_commitments.2.x.a},
						{register_commitments.2.x.b},
						{register_commitments.2.x.c}
                    ),
                    Bw6Fp(
						{register_commitments.2.y.a},
						{register_commitments.2.y.b},
						{register_commitments.2.y.c}
                    )
                    )
            }),
            additional_commitments: BitmaskPackingCommitments(\\{
                c_comm: Bw6G1(
                    Bw6Fp(
						{additional_commitments.0.x.a},
                        {additional_commitments.0.x.b},
                        {additional_commitments.0.x.c}
                    ),
                    Bw6Fp(
						{additional_commitments.0.y.a},
                        {additional_commitments.0.y.b},
                        {additional_commitments.0.y.c}
                    )
                    ),
                acc_comm: Bw6G1(
                    Bw6Fp(
						{additional_commitments.1.x.a},
                        {additional_commitments.1.x.b},
                        {additional_commitments.1.x.c}
                    ),
                    Bw6Fp(
						{additional_commitments.1.y.a},
                        {additional_commitments.1.y.b},
                        {additional_commitments.1.y.c}
                    )
                    )
            }),
            q_comm: Bw6G1(\\{
                x: Bw6Fp(\\{
                    a: {q_comm.x.a},
                    b: {q_comm.x.b},
                    c: {q_comm.x.c}
                }),
                y: Bw6Fp(\\{
                    a: {q_comm.y.a},
                    b: {q_comm.y.b},
                    c: {q_comm.y.c}
                })
            }),
            register_evaluations: SuccinctAccountableRegisterEvaluations(\\{
                c: Bw6Fr({register_evaluations.c.a}, {register_evaluations.c.b}),
                acc: Bw6Fr({register_evaluations.acc.a}, {register_evaluations.acc.b}),
                basic_evaluations: AffineAdditionEvaluations(\\{
                    keyset: [
                        Bw6Fr(\\{
							a: {register_evaluations.basic_evaluations.keyset.0.a},
							b: {register_evaluations.basic_evaluations.keyset.0.b}
                        }),
                        Bw6Fr(\\{
							a: {register_evaluations.basic_evaluations.keyset.1.a},
							b: {register_evaluations.basic_evaluations.keyset.1.b}
                        })
                    ],
                    bitmask: Bw6Fr(
						{register_evaluations.basic_evaluations.bitmask.a}, {register_evaluations.basic_evaluations.bitmask.b}
                        ),
                    partial_sums: [
                        Bw6Fr(\\{
							a: {register_evaluations.basic_evaluations.partial_sums.0.a},
							b: {register_evaluations.basic_evaluations.partial_sums.0.b}
                        }),
                        Bw6Fr(\\{
							a: {register_evaluations.basic_evaluations.partial_sums.1.a},
							b: {register_evaluations.basic_evaluations.partial_sums.1.b}
                        })
                    ]
                })
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

pub fn print_packed_proof(packed_proof: &PackedProof) {
    let mut tt = TinyTemplate::new();
    tt.add_template("packed_proof", SIMPLE_PROOF_TEMPLATE)
        .unwrap();

    let register_commitments = &packed_proof.register_commitments;
    let register_commitments0 = Bw6G1::from(register_commitments.partial_sums.0);
    let register_commitments1 = Bw6G1::from(register_commitments.partial_sums.1);
    let register_commitments2 = Bw6G1::from(register_commitments.bitmask);
    let additional_commitments = &packed_proof.additional_commitments;
    let c_comm = Bw6G1::from(additional_commitments.c_comm);
    let acc_comm = Bw6G1::from(additional_commitments.acc_comm);

    let q_comm = Bw6G1::from(packed_proof.q_comm);
    let keyset0 = packed_proof.register_evaluations.basic_evaluations.keyset.0;
    let keyset1 = packed_proof.register_evaluations.basic_evaluations.keyset.1;
    let partial_sums0 = packed_proof
        .register_evaluations
        .basic_evaluations
        .partial_sums
        .0;
    let partial_sums1 = packed_proof
        .register_evaluations
        .basic_evaluations
        .partial_sums
        .1;
    let c = packed_proof.register_evaluations.c;
    let acc = packed_proof.register_evaluations.acc;
    let b = packed_proof.register_evaluations.basic_evaluations.bitmask;
    let register_evaluations = SARE {
        c: Uint512::from_fr(c),
        acc: Uint512::from_fr(acc),
        basic_evaluations: AE {
            keyset: (Uint512::from_fr(keyset0), Uint512::from_fr(keyset1)),
            bitmask: Uint512::from_fr(b),
            partial_sums: (
                Uint512::from_fr(partial_sums0),
                Uint512::from_fr(partial_sums1),
            ),
        },
    };

    let context = PP {
        register_commitments: (
            register_commitments0,
            register_commitments1,
            register_commitments2,
        ),
        additional_commitments: (c_comm, acc_comm),
        q_comm,
        register_evaluations,
        q_zeta: Uint512::from_fr(packed_proof.q_zeta),
        r_zeta_omega: Uint512::from_fr(packed_proof.r_zeta_omega),
        w_at_zeta_proof: Bw6G1::from(packed_proof.w_at_zeta_proof),
        r_at_zeta_omega_proof: Bw6G1::from(packed_proof.r_at_zeta_omega_proof),
    };

    let rendered = tt.render("packed_proof", &context).unwrap();
    println!("{}", rendered);
}
