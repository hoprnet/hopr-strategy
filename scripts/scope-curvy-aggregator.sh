#!/usr/bin/env bash
#
# Grant a node's Safe permission to call the Curvy aggregator, which a direct-shield PIX deposit
# needs and which nothing does automatically.
#
# WHY THIS EXISTS
#
# `CurvyVaultV2` pulls a direct shield's funds with
# `safeTransferFrom(msg.sender_of_the_aggregator_call, vault, amount)`, so the account holding the
# wxHOPR must itself call `directShield`. For a HOPR node that account is its Safe, and the Safe
# acts only through `HoprNodeManagementModule.execTransactionFromModule`, which checks every inner
# call against the module's target set. wxHOPR is already a target — `approve` passes today — but
# the Curvy aggregator is not, so a shield reverts with `NonExistentKey()` until it is added.
#
# WHAT IT GRANTS, AND WHAT THAT COSTS
#
# The module's selector whitelist is hardcoded and knows nothing of `directShield`, so a
# selector-scoped grant cannot express this. The only encoding that works is
# `TargetPermission.ALLOW_ALL`, which short-circuits that whitelist:
#
#     the Safe may call THIS ONE ADDRESS with ANY selector and ANY calldata.
#
# It is scoped to one address and confers nothing anywhere else, and it cannot move native
# currency (the module rejects a non-zero `value` for a non-`SEND` target). But it is broader than
# a selector grant would be, so point it at an aggregator address you have verified. HOPR ship the
# same recipe as `addAllAllowedTargetToModuleBySafe` in `script/SingleAction.s.sol`, commented
# "Abuse TOKEN type" — `TargetType.TOKEN` is a label here, not a claim that the aggregator is one.
#
# The grant is idempotent-ish: re-scoping an address already in the set reverts `TargetIsScoped()`,
# so a second run fails loudly rather than silently doing nothing. `revokeTarget` undoes it.
#
# USAGE
#
#   # Print what to execute, for a Safe you drive through its UI or your own tooling:
#   ./scripts/scope-curvy-aggregator.sh --module 0xMODULE --aggregator 0xAGGREGATOR
#
#   # Execute it, for a 1-of-n Safe whose owner key you hold (dev clusters):
#   ./scripts/scope-curvy-aggregator.sh --module 0xMODULE --aggregator 0xAGGREGATOR \
#       --safe 0xSAFE --rpc-url http://127.0.0.1:8545 --owner-key 0xPRIVATEKEY
#
#   # Check the encoder against its reference vectors:
#   ./scripts/scope-curvy-aggregator.sh --self-test
#
# Execution needs `cast` (foundry); printing needs nothing.

set -euo pipefail

MODULE=""
AGGREGATOR=""
SAFE=""
RPC_URL=""
OWNER_KEY=""
SELF_TEST=0

# `scopeTargetToken(uint256)` — keccak256 of the signature, first four bytes.
SCOPE_SELECTOR="a76c9a2f"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --module)     MODULE="${2:-}"; shift 2 ;;
    --aggregator) AGGREGATOR="${2:-}"; shift 2 ;;
    --safe)       SAFE="${2:-}"; shift 2 ;;
    --rpc-url)    RPC_URL="${2:-}"; shift 2 ;;
    --owner-key)  OWNER_KEY="${2:-}"; shift 2 ;;
    --self-test)  SELF_TEST=1; shift ;;
    -h|--help)    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;$d'; exit 0 ;;
    *)            die "unknown argument $1" ;;
  esac
done

# Strips `0x` and lowercases, so every downstream concatenation sees one spelling.
normalise_address() {
  local raw="${1#0x}"
  raw="${raw#0X}"
  printf '%s' "$raw" | tr 'A-F' 'a-f'
}

# The module's `Target`: a packed uint256 laid out by `TargetUtils.encodeDefaultPermissions` as
#
#   address << 96 | Clearance << 88 | TargetType << 80 | TargetPermission << 72 | 9 capability bytes
#
# which for our grant is the 20-byte address followed by
#
#   01  Clearance.FUNCTION       — the target is callable at all
#   00  TargetType.TOKEN         — the label the module files it under
#   03  TargetPermission.ALLOW_ALL — any selector
#   00 x9  every capability left at NONE, so the ALLOW_ALL default is what applies
encode_target() {
  local address
  address="$(normalise_address "$1")"
  [ "${#address}" -eq 40 ] || die "not a 20-byte address: $1"
  printf '0x%s010003%s' "$address" "000000000000000000"
}

if [ "$SELF_TEST" -eq 1 ]; then
  # Vectors computed from the layout above, independently of this script.
  expected_c="0xcccccccccccccccccccccccccccccccccccccccc010003000000000000000000"
  expected_1="0x0000000000000000000000000000000000000001010003000000000000000000"
  actual_c="$(encode_target 0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC)"
  actual_1="$(encode_target 0000000000000000000000000000000000000001)"
  [ "$actual_c" = "$expected_c" ] || die "target encoding drifted: $actual_c != $expected_c"
  [ "$actual_1" = "$expected_1" ] || die "target encoding drifted: $actual_1 != $expected_1"
  # 32 bytes, not 31 or 33 — a length slip here would be accepted as a different target.
  [ "${#actual_c}" -eq 66 ] || die "target is not 32 bytes: ${#actual_c} chars"
  # The selector an operator pastes into a Safe UI, pinned against its known value.
  # `cast sig 'scopeTargetToken(uint256)'` reproduces it if you want to re-derive it.
  [ "$SCOPE_SELECTOR" = "a76c9a2f" ] || die "scopeTargetToken selector drifted: $SCOPE_SELECTOR"
  echo "self-test passed: target encoding and selector match their reference vectors"
  exit 0
fi

[ -n "$MODULE" ] || die "--module is required (the node's HoprNodeManagementModule)"
[ -n "$AGGREGATOR" ] || die "--aggregator is required (the Curvy aggregator to allow)"

TARGET="$(encode_target "$AGGREGATOR")"

# Hardcoded rather than shelled out to `cast`, so the printed calldata is identical whether or
# not foundry is installed: this is what an operator pastes into a Safe UI, and a value that
# varies by toolchain is a value nobody can check. The self-test pins it.
#
# The argument is a bare uint256, so the calldata is the selector followed by the packed word.
SCOPE_CALLDATA="0x${SCOPE_SELECTOR}${TARGET#0x}"

cat <<INFO
Curvy aggregator : $AGGREGATOR
Module           : $MODULE
Target (packed)  : $TARGET

Execute FROM THE SAFE (the module's owner):

  to    : $MODULE
  value : 0
  data  : $SCOPE_CALLDATA

INFO

if [ -z "$OWNER_KEY" ]; then
  cat <<'INFO'
No --owner-key given, so nothing was sent. Submit the call above as a Safe transaction — through
the Safe UI, or with whatever tooling drives your Safe.
INFO
  exit 0
fi

[ -n "$SAFE" ] || die "--safe is required to execute"
[ -n "$RPC_URL" ] || die "--rpc-url is required to execute"
command -v cast >/dev/null 2>&1 || die "cast (foundry) is required to execute"

OWNER="$(cast wallet address --private-key "$OWNER_KEY")"

# A Safe accepts a "pre-validated" signature from an owner who is also the sender: r = the owner
# address, s = 0, v = 1. That avoids EIP-712 signing entirely, and works only because this call
# comes straight from the owner — which is exactly the dev-cluster case this branch is for.
OWNER_WORD="$(normalise_address "$OWNER")"
SIGNATURE="0x000000000000000000000000${OWNER_WORD}$(printf '0%.0s' $(seq 1 64))01"

echo "Executing as Safe owner $OWNER ..."
cast send "$SAFE" \
  'execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)' \
  "$MODULE" 0 "$SCOPE_CALLDATA" 0 0 0 0 \
  0x0000000000000000000000000000000000000000 \
  0x0000000000000000000000000000000000000000 \
  "$SIGNATURE" \
  --rpc-url "$RPC_URL" --private-key "$OWNER_KEY"

echo "Scoped $AGGREGATOR into module $MODULE."
