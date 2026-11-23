# Result figures (W26, CONTRACT §13)

Every figure below is drawn from committed experiment outputs by one script, `make_figs2.py`.
The script hard-codes no numbers. Where two sources overlap, it `assert`s they agree before it draws
(for example, `aggregate.json` against the raw `resolution.csv` files, and the FRR Wilson intervals
recomputed from counts).

```sh
cd binding/paper/figs
/usr/bin/python3 make_figs2.py        # writes all six fig_*.pdf and prints the aggregates it plotted
```

**Environment.** Rendered with matplotlib 3.9.4 and numpy 2.0.2 (macOS system Python 3.9). `requirements.txt` pins
matplotlib 3.9.2 and numpy 2.1.2; any matplotlib ≥ 3.9 works. The script assumes `aggregate.json` already exists.
That file is written by `make_figs.py`, which needs `analysis/figstyle.py`; it is not re-run here.

**Style.** Follows the figures4papers house style (scientific-figure-making skill):
- Arial (embedded as TrueType, `pdf.fonttype 42`); top and right spines off; frameless legends; black bar edges.
- Colour semantics: blue = G1 or baseline; red = G2, the finding, or a defence.
- Every class also has a hatch, so the figures stay readable in greyscale.
- No in-figure titles.
- All output is pure vector. The heatmap uses `pcolormesh`, so it embeds no raster (`pdfimages -list` is empty).
- Sizes: designed at 7.0 in (full width) or 3.33 in (one column), with 7–7.5 pt text. `bbox_inches=tight` trims the
  margins, so the full-width PDFs come out about 5.9–6.0 in wide. Include them with `width=\textwidth`; the text then
  scales to about 8.5 pt.

| file | size | page (pt) | width | fonts |
|---|---|---|---|---|
| fig_hits_heatmap.pdf | 28.7 KB | 424.6 × 145.3 | full | ArialMT |
| fig_resolution.pdf | 30.4 KB | 217.2 × 136.3 | column | ArialMT, Arial-Italic, Cmex10 (the `\widehat`) |
| fig_class.pdf | 37.5 KB | 431.4 × 150.2 | full | ArialMT, Arial-Bold |
| fig_ablation_a1.pdf | 79.1 KB | 431.3 × 151.3 | full | ArialMT, Arial-Bold |
| fig_defence.pdf | 82.5 KB | 422.7 × 155.7 | full | ArialMT, Arial-Bold |
| fig_latency.pdf | 83.9 KB | 422.0 × 144.8 | full | ArialMT, Arial-Bold |

All six were checked with `pdfinfo`: each is 1 page, PDF 1.4. `pdffonts` reports every font as `emb yes`, `sub yes`.

---

## 1. fig_hits_heatmap.pdf
- **Command:** `make_figs2.py` → `fig_hits_heatmap()`
- **Data:** `paper/figs/aggregate.json`, keys `heatmap_g1`, `heatmap_g2`, `heatmap_topologies_per_cell` (asserted = 4 for
  all 48 cells), `heatmap_g1_total` (2412) and `heatmap_g2_total` (240). These keys are built by `make_figs.py` from
  `experiments/{kill,ext-gw,ext-fw}/analysis/{hits_per_topology.csv,hits_all.jsonl}`.
- **Scope:** v1 route space, edge placement. Each cell sums 2 profiles × 2 override settings. Classes are by mechanism:
  RC7 (`#` landing in the unbound query) counts as G1, as in `make_figs.py`.
- **Caption suggestion:** "Binding hits per gateway × framework (edge placement, v1 routes; each cell sums four
  topologies). (a) G1 under-binding is present in every cell; (b) G2 differentials are confined to NGINX/Kong ×
  FastAPI/chi/Laravel and APISIX × Express/chi/ASP.NET/Rails."
- Supersedes `hits_heatmap.pdf`, which `make_figs.py` still writes and `sections/harness.tex:294` still includes. W25
  should switch the include to `fig_hits_heatmap.pdf`.

## 2. fig_resolution.pdf
- **Command:** `fig_resolution()`
- **Data:** `aggregate.json` keys `leak.<campaign>.res_hat` and `leak_res_hat_total`. These are re-derived from
  `experiments/{kill,ext-gw,ext-fw,ext-routes}/analysis/resolution.csv` and asserted equal.
- **Unit:** one (topology, base op) pair. n = 3,168.
- **Values:**

  | res | v1 (kill + ext-gw + ext-fw) | v2 (ext-routes) |
  |---|---|---|
  | 1 | 2,245 | 176 |
  | 2 | 228 | 40 |
  | 3 | 427 | 19 |
  | 4 | 12 | 16 |
  | 5 | 0 | 3 |
  | 6 | 0 | 2 |

- **Caption suggestion:** "Distribution of binding resolution $\widehat{res}$, the number of distinct operations a single
  valid proof reaches, over all (topology, base-op) pairs. Log scale; $\widehat{res}>1$ violates binding soundness."
- **Data gap:** CONTRACT §13 says "res_hat 1..4", but the committed data reaches **6** (5 pairs, all in the v2 route
  space). The figure shows 1–6, and the text should not say "1–4".

## 3. fig_class.pdf
- **Command:** `fig_class()`
- **Data:**
  - (a) `experiments/<campaign>/analysis/hits_all.jsonl` for kill, ext-gw, ext-fw and ext-routes, classified with the
    `make_figs.py` mechanism rule and asserted equal to `aggregate.json` `leak.<campaign>.mech_class`. G1/G2 per
    campaign: kill 656/24, ext-gw 1,200/168, ext-fw 646/48, ext-routes 116/110. G3 = 0 everywhere, asserted.
  - (b) primitive family. Each hit's single minimal primitive is mapped through
    `harness/mutator/primitives/{g1,g2}.yaml` (`class:` field); W15's `x-frag-*` primitives map to "fragment".
    Totals:

    | family | hits |
    |---|---|
    | query dispatch | 975 |
    | body `_method` | 700 |
    | JSON-body dispatch | 650 |
    | `#` fragment | 234 (198 G2, 36 G1 via RC7) |
    | header override | 136 |
    | Content-Type relabel | 101 |
    | `%2f` | 96 |
    | dot segment | 56 |
    | query `_method` | 20 |

- **Caption suggestion:** "(a) Binding hits per campaign by class: G1 dominates; G2 contributes 350 of 2,968; no G3
  binding hit was observed. (b) Hits per primitive family across all campaigns."
- **Optional cross-check:** kill/G1_REPORT.md §1 reports *oracle* classes (g1 648 / g2 32), while the figure uses
  *mechanism* classes. The 8-hit difference is RC7, explained in the `make_figs.py` docstring. The caption or text
  should say "by mechanism".

## 4. fig_ablation_a1.pdf
- **Command:** `fig_ablation_a1()`
- **Data:**
  - (a) `experiments/ablation/analysis/a1_variant_summary.csv`: mutation set, 8 topologies per variant, columns
    g1/g2/other.
  - (b) `experiments/ablation/analysis/a1_runs_swap_variant_summary.csv`: swap set.
- **Values (a):** full 192, −htm 192, −htu 432, −ath 192, +query 147, +digest (no gate) 192, +digest 129,
  +query+digest 84.
- **Values (b):** full 0, −htm 192, −htu 720, all other variants 0.
- **Caption suggestion:** "A1 binding-claim ablation. (a) Residual hits on the mutation set: htu does nearly all the work;
  binding the query (+query) and the body (+digest, with a body-seeing gate) remove 108 G1 hits, but the 60 G2 hits
  survive every variant. (b) Cross-op/method-swap replay: htm and htu each prevent replay that the mutation corpus
  cannot see."
- **Discrepancy with the brief (reported, not papered over):** the brief asked to annotate that "+query/+digest drive
  residual to the by-design floor". The data does not support that wording.
  - +query+digest leaves **84** hits: **24 header-carried G1** (X-HTTP-Method-Override M5a/M5b, Content-Type relabel
    M3, `#` in the query M7) plus **60 G2** (ablation/REPORT.md §A1.3 item 6).
  - The figure annotates exactly that: the −108 reduction, the 24 G1 left over, and a dashed line at the 60 G2 hits
    that no binding variant removes.

## 5. fig_defence.pdf
- **Command:** `fig_defence()`
- **Data (a):** `experiments/defence/analysis/e7_aleak_long.csv`, rows with `hit == True` counted by `cfg` × `class`.
  These match `e7_tables.md`: B-edge 229, B-origin 217, B-strict 205, D-A 146, D-B 146, D-C 205.
- **Data (b):** `experiments/defence/analysis/frr_summary.json`, attributable FRR. Wilson 95% CIs are recomputed from
  `att`/`att_n` and asserted equal; they match `frr_tables.md`.

  | config | FRR | 95% CI |
  |---|---|---|
  | B-edge | 0.0% | [0.0, 0.8] |
  | B-origin | 40.0% | [35.8, 44.4] |
  | B-strict | 28.8% | [25.0, 32.9] |
  | D-A | 43.2% | [38.9, 47.6] |
  | D-B | 43.2% | [38.9, 47.6] |
  | D-C | 28.8% | [25.0, 32.9] |

  n = 500 for every config.
- **Caption suggestion:** "Defence trade-off. (a) Residual binding hits on the 229 E7 witnesses: D-A and D-B remove
  method override and every G2 hit, while query/body G1 (146) remains by design. (b) Attributable false rejection on
  legitimate path-rewriting traffic (S0–S5, NGINX, 4 frameworks, n = 500; Wilson 95% CI): D-A/D-B reject 43% because
  strip-prefix, version-rewrite and trailing-slash rewrites change the routed view."
- **Notes:**
  - B-optional (also in e7_tables.md, 229 hits, identical to B-edge) is omitted. It is not in the §13 config list and
    has no FRR row.
  - The FRR is from the NGINX gateway only. The W23 cross-gateway FRR (`experiments/gaps/frr/`) is empty in the tree,
    so no cross-gateway FRR was plotted.
  - Panel (b) shows the attributable FRR, not the raw FRR (B-edge raw is 3.1%, from 16 S4 pct-id requests that fail
    under every config).

## 6. fig_latency.pdf
- **Command:** `fig_latency()`
- **Data:** `experiments/defence/analysis/perf_latency.csv`, rows with `level == 100` only. `failed_checks` is asserted
  to be 0 for every plotted row. The error bars are the file's `p*_lo` / `p*_hi`: the 95% CI over 5 runs, as labelled in
  `perf_tables.md`.
- **Configs:** B-edge, B-origin, D-A and D-B, in two panels (FastAPI, Spring). D-C has no perf row. B-origin is
  included because it is the same-hop baseline for D-A.
- **Excluded:** the rows at 500, 1000 and max req/s, as noted inside the figure. defence/REPORT.md §6 shows that every
  failure there is an nginx 502 (connection refused) from laptop saturation, not reproducible from run to run, so those
  rows say nothing about the defences' latency.
- **Caption suggestion:** "Latency at 100 req/s (no errors; median of 5 runs, 95% CI; log scale). D-B's median is
  indistinguishable from B-edge on both frameworks (Cliff's δ negligible; its FastAPI p99 CI is wide, 7.7–102.6 ms); D-A's FastAPI tail (p95 149 ms, p99 992 ms) comes from the FastAPI
  executor's origin-mode verifier call, not from D-A itself (Spring D-A tracks B-edge). Rows at ≥500 req/s are omitted
  as 502 saturation."
- **Data gaps:**
  - The numbers are from the laptop run. `experiments/perf-server/results/raw/` (W24 remote re-run) is empty, so there
    is no server-grade latency to plot.
  - The FastAPI D-A tail attribution is W17's reading (defence/REPORT.md §6), not something re-measured here.
