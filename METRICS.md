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
