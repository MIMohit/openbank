# Manuscript and supporting material

| File | What it is |
|---|---|
| `manuscript.md` | The manuscript. Rewritten from the implementation and the measured data; every number in it is checked against `data/tables/` by `make verify-manuscript`. |
| `figures/` | The twelve figures the manuscript cites, as vector PDF for typesetting and 400 dpi PNG for preview. Built by `make figures` from the code and the committed records; nothing in them is entered by hand. |
| `ASSESSMENT.md` | A simulated peer review at the target venue's standard, the direct answers to "what must change before submission", and the prioritised list of additional experiments and system modifications with their rationale, metrics and expected effect. |
| `CLAIMS_CHANGED.md` | Every claim the previous manuscript made that this one does not, or makes differently, with the evidence that forced each change. |
| `Paper_V1_Rewrite.pdf` | The original scaffold draft, kept for provenance. It predates any measurement and its `[FILL]`/`[VERIFY]` placeholders were never data. Do not cite it. |

The reproducibility checklist is §13 of the manuscript. The previous manuscript (`paper.md`, internally "V2") is superseded by `manuscript.md` and remains in git history at commit `b2d4253`.

## Rebuilding everything

```bash
make analysis            # tables from the committed raw records, then all figures
make verify-manuscript   # fail if any number in the prose no longer matches the data
```

To reproduce the measurements themselves rather than the artefacts, see the top-level `README.md`.
