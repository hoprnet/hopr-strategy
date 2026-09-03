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
discoverable only by a per-SSA scan identity the Exit mints, and recovered deposits are withdrawn from it to the Safe. At runtime it needs a
Blokli endpoint that exposes the Curvy deployment, the Curvy operator's EVM key in the environment (`HOPRD_CURVY_OPERATOR_PRIVATE_KEY` by
default), the Curvy Groth16 proving artifacts (`CURVY_ZK_KEYS_DIR`: the five zkeys and five witness graphs published with each
[`rs-sdk` release](https://github.com/0xCurvy/rs-sdk/releases), digest-checked on load), and a state file that survives restarts; see the
`pix::pools::curvy` module documentation.

Enabling `strategy-pix` alone gives the engine without a pool, for a consumer supplying its own.

## License

GPL-3.0-only
