# hopr-strategy

Contains implementations of different HOPR strategies

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Strategies

Each strategy is gated behind its own Cargo feature, so a consumer compiles only what it runs.

| strategy          | module              | feature                      |
| ----------------- | ------------------- | ---------------------------- |
| Multi / passive   | `strategy`          | _(always available)_         |
| Auto funding      | `auto_funding`      | `strategy-auto-funding`      |
| Auto redeeming    | `auto_redeeming`    | `strategy-auto-redeeming`    |
| Closure finalizer | `channel_finalizer` | `strategy-closure-finalizer` |
| Channel lifecycle | `channel_lifecycle` | `strategy-channel-lifecycle` |
| PIX               | `pix`               | `strategy-pix`               |

`MultiStrategy` runs any combination of them concurrently, and accepts strategies defined outside this crate.

### PIX deposit pools

The PIX strategy drives a `DepositPool`, which must settle to the same deposit-address scheme the node's PIX spec produces. Each pool ships
as its own feature and module, to be paired with the matching `hopr-lib/pix-*` feature:

| feature              | module              | deposit address | pair with                |
| -------------------- | ------------------- | --------------- | ------------------------ |
| `strategy-pix-test`  | `pix::pools::plain` | `Address`       | `hopr-lib/pix-secp256k1` |
| `strategy-pix-curvy` | `pix::pools::curvy` | `BjjPublicKey`  | `hopr-lib/pix-bjj`       |

Both may be enabled at once; the pool is chosen at the call site rather than by the feature graph. Passing the node's deposit-address type
to the builder makes a mismatched pairing a compile error instead of a per-event runtime failure.

`strategy-pix-test` settles with plain, fully visible on-chain transfers and is **not for production use**.

`strategy-pix-curvy` settles anonymously through the [Curvy](https://curvy.box) shielded pool: deposits are allocations inside the pool,
discoverable only by a per-SSA scan identity the Exit mints, and recovered deposits are withdrawn from it to the Safe.

It offers two independent choices, because the Curvy relayer never handles deposits — a shield is a self-signed transaction either way:

| setting | default | alternative |
| ------- | ------- | ----------- |
| `shielding` | `direct` — the node's Safe calls `directShield`, with no entry portal | `portal` — fund a deterministic entry portal, then deploy and shield it |
| `submission` | `relayer` — hand proofs to Curvy's off-chain relayer | `operator` — sign and submit them from this node |

Both defaults describe a production deployment; a cluster without Curvy's off-chain services runs `submission: operator`.
A **direct shield never takes the float out of the Safe**: the vault pulls from whoever calls `directShield`, so the Safe itself makes that
call through its permission module. That needs a one-time grant per Safe — `scripts/scope-curvy-aggregator.sh` prints the transaction — and
the node's own chain key to sign the module call.

At runtime it needs a Blokli endpoint that exposes the Curvy deployment, the Curvy Groth16 proving artifacts (`CURVY_ZK_KEYS_DIR`: the five
zkeys and five witness graphs published with each [`rs-sdk` release](https://github.com/0xCurvy/rs-sdk/releases), digest-checked on load),
and a state file that survives restarts. Under `submission: relayer` it also needs a relayer URL, and **no EVM key of its own**; under
`submission: operator` it needs the Curvy operator's key in the environment (`HOPRD_CURVY_OPERATOR_PRIVATE_KEY` by default). See the
`pix::pools::curvy` module documentation.

Enabling `strategy-pix` alone gives the engine without a pool, for a consumer supplying its own.

## License

GPL-3.0-only
