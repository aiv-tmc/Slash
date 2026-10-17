//! Page roots and proofs: leaves come from the range map itself (the
//! short final page behaves like any other), an empty page fails loudly,
//! and the global root is deterministic.

use super::*;

#[test]
fn merkle_root_and_proof() {
    // Proofs verify against the root for leaves in every range of a
    // three-range page.
    let mut page = Page {
        ranges: BTreeMap::new(),
    };
    page.ranges.insert(
        0,
        R {
            e: 10,
            o: [1u8; 32],
        },
    );
    page.ranges.insert(
        10,
        R {
            e: 20,
            o: [2u8; 32],
        },
    );
    page.ranges.insert(
        20,
        R {
            e: 30,
            o: [3u8; 32],
        },
    );

    let root = page.merkle_root();
    let proof = page.merkle_proof(5).unwrap();
    assert!(verify_page_proof(&root, &proof));

    let proof2 = page.merkle_proof(15).unwrap();
    assert!(verify_page_proof(&root, &proof2));

    let proof3 = page.merkle_proof(25).unwrap();
    assert!(verify_page_proof(&root, &proof3));
}

#[test]
#[should_panic(expected = "merkle_root of an empty page")]
fn merkle_root_of_empty_page_fails_loudly() {
    // A detached page with an empty range map is a construction error;
    // hashing it must panic with a diagnostic instead of silently
    // producing the root of a wrong implicit page (the hazard an
    // implicit page-id fallback would create).
    let page = Page {
        ranges: BTreeMap::new(),
    };
    let _ = page.merkle_root();
}

#[test]
fn merkle_proof_uses_actual_range_ends() {
    // The leaf boundaries come from the range map itself, so the short
    // final page behaves exactly like any other: offsets inside the
    // last range get a proof, offsets at or beyond its end get none.
    // page_count returns a u16, so the final page id feeds page_size
    // directly without a cast.
    let final_len = page_size(page_count() - 1);
    assert!(final_len < PAGE_SIZE);
    let mut page = Page {
        ranges: BTreeMap::new(),
    };
    page.ranges.insert(
        0,
        R {
            e: final_len,
            o: TREASURY,
        },
    );
    let root = page.merkle_root();
    let proof = page.merkle_proof(final_len - 1).unwrap();
    assert!(verify_page_proof(&root, &proof));
    assert!(page.merkle_proof(final_len).is_none());
    assert!(page.merkle_proof(PAGE_SIZE - 1).is_none());
}

#[test]
fn global_root_is_deterministic() {
    // The global root commits to every page id paired with its root and
    // is a pure function of the state: repeated computations agree.
    let state = State::genesis();
    let r1 = state.global_root();
    let r2 = state.global_root();
    assert_eq!(r1, r2);
}
