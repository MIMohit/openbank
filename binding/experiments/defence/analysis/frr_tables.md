Frameworks: aspnet, express, fastapi, spring (nginx gateway). Cell = attributable false rejects / requests B-edge executed correctly (raw failures in parentheses).

| scenario | B-edge | B-origin | B-strict | D-A | D-B | D-C |
|---|---|---|---|---|---|---|
| S0-identity | 0/68 (0/68) | 0/68 (0/68) | 0/68 (0/68) | 4/68 (4/68) | 4/68 (4/68) | 0/68 (0/68) |
| S1-strip-prefix | 0/68 (0/68) | 68/68 (68/68) | 0/68 (0/68) | 68/68 (68/68) | 68/68 (68/68) | 0/68 (0/68) |
| S2-version-rewrite | 0/64 (0/64) | 64/64 (64/64) | 0/64 (0/64) | 64/64 (64/64) | 64/64 (64/64) | 0/64 (0/64) |
| S3-trailing-slash | 0/68 (0/68) | 68/68 (68/68) | 0/68 (0/68) | 68/68 (68/68) | 68/68 (68/68) | 0/68 (0/68) |
| S4-pct-id | 0/164 (16/180) | 0/164 (16/180) | 144/164 (160/180) | 8/164 (24/180) | 8/164 (24/180) | 144/164 (160/180) |
| S5-h2-to-h1 | 0/68 (0/68) | 0/68 (0/68) | 0/68 (0/68) | 4/68 (4/68) | 4/68 (4/68) | 0/68 (0/68) |
| ALL | 0/500 (16/516) | 200/500 (216/516) | 144/500 (160/516) | 216/500 (232/516) | 216/500 (232/516) | 144/500 (160/516) |

| config | attributable FRR [95% Wilson CI] | raw FRR [95% CI] |
|---|---|---|
| B-edge | 0.0% [0.0, 0.8] (0/500) | 3.1% [1.9, 5.0] (16/516) |
| B-origin | 40.0% [35.8, 44.4] (200/500) | 41.9% [37.7, 46.2] (216/516) |
| B-strict | 28.8% [25.0, 32.9] (144/500) | 31.0% [27.2, 35.1] (160/516) |
| D-A | 43.2% [38.9, 47.6] (216/500) | 45.0% [40.7, 49.3] (232/516) |
| D-B | 43.2% [38.9, 47.6] (216/500) | 45.0% [40.7, 49.3] (232/516) |
| D-C | 28.8% [25.0, 32.9] (144/500) | 31.0% [27.2, 35.1] (160/516) |

Attributable false rejects by cause (status + body reason):

| config | scenario | status/reason | n |
|---|---|---|---|
| B-origin | S1-strip-prefix | `401 null` | 68 |
| B-origin | S2-version-rewrite | `401 null` | 64 |
| B-origin | S3-trailing-slash | `401 null` | 68 |
| B-strict | S4-pct-id | `400 <html>` | 144 |
| D-A | S0-identity | `401 null` | 4 |
| D-A | S1-strip-prefix | `401 null` | 68 |
| D-A | S2-version-rewrite | `401 null` | 64 |
| D-A | S3-trailing-slash | `401 null` | 68 |
| D-A | S4-pct-id | `401 null` | 8 |
| D-A | S5-h2-to-h1 | `401 null` | 4 |
| D-B | S0-identity | `401 view_mac_mismatch` | 4 |
| D-B | S1-strip-prefix | `401 view_mac_mismatch` | 68 |
| D-B | S2-version-rewrite | `401 view_mac_mismatch` | 64 |
| D-B | S3-trailing-slash | `401 view_mac_mismatch` | 68 |
| D-B | S4-pct-id | `401 view_mac_mismatch` | 8 |
| D-B | S5-h2-to-h1 | `401 view_mac_mismatch` | 4 |
| D-C | S4-pct-id | `400 <html>` | 144 |
