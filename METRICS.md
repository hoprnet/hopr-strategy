| Name                                                  | Type          | Description                                                                           | Detail           |
| ----------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------- | ---------------- |
| `hopr_strategy_auto_funding_failure_count`            | SimpleCounter | Count of failed automatic funding attempts                                            |                  |
| `hopr_strategy_auto_funding_funding_count`            | SimpleCounter | Count of initiated automatic fundings                                                 |                  |
| `hopr_strategy_auto_redeem_redeem_count`              | SimpleCounter | Count of initiated automatic redemptions                                              |                  |
| `hopr_strategy_channel_lifecycle_bucket_count`        | MultiGauge    | Number of open channels in each (latency, subnet) bucket cell                         | keys: cell       |
| `hopr_strategy_channel_lifecycle_closes`              | SimpleCounter | Count of initiated channel closures                                                   |                  |
| `hopr_strategy_channel_lifecycle_effective_buckets`   | SimpleGauge   | Effective number of distinct (latency, subnet) bucket cells among open channels (2^H) |                  |
| `hopr_strategy_channel_lifecycle_finalizations`       | SimpleCounter | Count of initiated channel closure finalizations                                      | buckets: BUCKETS |
| `hopr_strategy_channel_lifecycle_fundings`            | SimpleCounter | Count of initiated channel fundings                                                   |                  |
| `hopr_strategy_channel_lifecycle_latency_variance_ms` | SimpleGauge   | Variance of round-trip times (ms) across all open channels                            |                  |
| `hopr_strategy_channel_lifecycle_opens`               | SimpleCounter | Count of initiated channel opens                                                      |                  |
| `hopr_strategy_channel_lifecycle_score_axis`          | MultiGauge    | Average per-axis score across open candidates in the last strategy tick               | keys: axis       |
| `hopr_strategy_channel_lifecycle_subnet_count`        | SimpleGauge   | Number of distinct subnet prefixes among open channels                                |                  |
| `hopr_strategy_closure_auto_finalization_count`       | SimpleCounter | Count of channels where closure finalizing was initiated automatically                |                  |
| `hopr_strategy_pix_deposit_data_total`                | MultiCounter  | Outcomes of the Exit asking its pool to generate PIX deposit data, per allocation     | keys: outcome    |
| `hopr_strategy_pix_deposit_tracking_total`            | MultiCounter  | Outcomes of the Exit waiting for an SSA deposit to land                               | keys: outcome    |
| `hopr_strategy_pix_deposits_failed_total`             | SimpleCounter | Count of SSA deposits that failed after exhausting retries                            |                  |
| `hopr_strategy_pix_deposits_over_budget_total`        | SimpleCounter | Count of SSA deposits refused because they would cross max_spend_per_window           |                  |
| `hopr_strategy_pix_deposits_rejected_total`           | SimpleCounter | Count of SSA deposits refused because they exceed max_ssa_allocation                  |                  |
| `hopr_strategy_pix_deposits_total`                    | SimpleCounter | Count of SSA deposits successfully sent by the Entry                                  |                  |
| `hopr_strategy_pix_keys_recovered_total`              | SimpleCounter | Count of SSA stealth address private keys reconstructed by the Exit                   |                  |
| `hopr_strategy_pix_last_sweep_hopr`                   | SimpleGauge   | wxHOPR moved by the most recent SSA sweep, in base units                              |                  |
| `hopr_strategy_pix_sweeps_total`                      | SimpleCounter | Count of recovered SSA deposits swept into the Exit's Safe                            |                  |
