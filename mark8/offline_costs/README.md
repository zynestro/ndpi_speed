# mark7 offline cost profiles

This directory is the default offline-rule directory used by `mark7`.

`lookup_table.json` decides which bucket a new flow belongs to:

```text
dst_port + payload_prefix -> Easy / Middle / Hard
```

`cost_profile.csv` decides how expensive that bucket is on P-core and E-core:

```text
core_type,bucket,cost_us
P,Easy,2.262390
P,Middle,7.626345
P,Hard,17.278661
E,Easy,2.262390
E,Middle,7.626345
E,Hard,17.278661
```

Format:

- `core_type`: `P` or `E`
- `bucket`: `Easy`, `Middle`, or `Hard`
- `cost_us`: offline profiling cost in microseconds

If only one core type is present, `mark7` copies those values to the missing core type. That makes it possible to start with P-core profiling and later replace the `E,*` rows after E-core profiling is ready.

The recommended bucket representative is printed by `mark5/train_port_prefix_lookup.py` as the flow-weighted mean of protocol `W_us` inside each bucket. This makes frequent protocols matter proportionally more than rare protocols.

Default runtime inputs:

```text
mark7/offline_costs/lookup_table.json
mark7/offline_costs/cost_profile.csv
```

To refresh the lookup table from mark5 profiling output, run `mark5/train_port_prefix_lookup.py` and copy its `lookup_table.json` here, or pass that generated file directly with `-m`.
