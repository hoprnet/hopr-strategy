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

| feature              | module           | deposit address | pair with                |
| -------------------- | ---------------- | --------------- | ------------------------ |
| `strategy-pix-test`  | `pix::secp256k1` | `Address`       | `hopr-lib/pix-secp256k1` |
| `strategy-pix-curvy` | `pix::curvy`     | `BjjPublicKey`  | `hopr-lib/pix-bjj`       |

Both may be enabled at once; the pool is chosen at the call site rather than by the feature graph. Passing the node's deposit-address type
to the builder makes a mismatched pairing a compile error instead of a per-event runtime failure.

`strategy-pix-curvy` is currently a **stub whose settlement methods panic** — the feature wiring is final, the settlement logic is not. Its
`generate_deposit_data` is the exception and returns an empty payload, so the deposit-data request path stays exercisable end to end.
`strategy-pix-test` settles with plain, fully visible on-chain transfers and is **not for production use**.

Enabling `strategy-pix` alone gives the engine without a pool, for a consumer supplying its own.

## License

GPL-3.0-only
