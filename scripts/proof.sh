#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

if command -v cargo-kani >/dev/null 2>&1; then
  CARGO_KANI="$(command -v cargo-kani)"
elif [ -x "$HOME/.cargo/bin/cargo-kani" ]; then
  CARGO_KANI="$HOME/.cargo/bin/cargo-kani"
else
  echo "cargo-kani is required. Install it with: cargo install --locked kani-verifier && cargo kani setup" >&2
  exit 1
fi

"$CARGO_KANI" --version >/dev/null

core_harnesses=(
  uint_argument_classifier_is_minimal
  encoded_uint_payload_roundtrips_through_checked_reader
  checked_uint_arg_ai24_matches_minimal_rule
  checked_uint_arg_ai25_matches_minimal_rule
  checked_uint_arg_ai26_matches_minimal_rule
  checked_uint_arg_ai27_matches_minimal_rule
  checked_len_rejects_indefinite_without_advancing
  float_profile_classifies_all_bit_patterns
  bignum_boundaries_are_classified
  text_key_payload_order_matches_encoded_order_for_short_payloads
  payload_comparator_equal_means_duplicate_key
  text_key_payload_order_is_transitive_for_short_payloads
  text_key_payload_order_is_antisymmetric_for_short_payloads
  encoder_poison_is_sticky_after_failed_array_callback
  encoder_poison_is_sticky_after_array_underfill
  encoder_root_slot_accepts_exactly_one_value
  encoder_array_slot_conservation_for_one_scalar
  encoder_poison_is_sticky_after_text_output_limit
)

abi_harnesses=(
  abi_id_validator_accepts_exact_nonzero_u32_range
  sorted_query_ids_accepts_exact_nonzero_singleton
  sorted_query_ids_accepts_exact_strict_nonzero_order_for_len3
  runtime_schema_ids_accept_exact_strict_nonzero_order_for_len3
)

for harness in "${core_harnesses[@]}"; do
  "$CARGO_KANI" --harness "$harness"
done

for harness in "${abi_harnesses[@]}"; do
  "$CARGO_KANI" -p sacp-cbor-abi --harness "$harness"
done
