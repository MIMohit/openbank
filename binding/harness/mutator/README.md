# mutator — primitive catalogue + deterministic compositor (W7)

Generates the mutation **cases** (CONTRACT §6) that the runner sends. A case is a base op
(a legitimate bench-API request with a valid proof) plus one or more applied primitives.

## Contents
- `base_ops.py` — the 13 canonical bench-API operations (CONTRACT §3) as byte-exact
  `RawRequest`s, each tagged for compatibility and carrying `@@AUTHZ@@`/`@@PROOF@@`
  placeholders the runner fills per case. Exposes `htu`/`htm` (the proof binding).
- `transforms.py` — the transform-function registry. Each YAML primitive's `transform` is
  an ordered list of `{fn, args}` steps resolved here. Generic, parametric functions keep
  the catalogue declarative while the byte manipulation lives in one tested place.
- `primitives/{g1,g2,g3}.yaml` — **the catalogue** (84 base primitives: G1=37, G2=32,
  G3=15; ≥60 required). Each entry has `id`, `class`, `description`, `source` (paper /
  advisory / RFC citation) and `transform`, plus an optional `applies_to` compatibility
  selector.
- `primitives/build_catalogue.py` — authoring tool that regenerates the YAML from
  structured Python (so ids/citations stay consistent). The YAML is the committed source of
  truth that `compose.py` reads.
- `catalogue.py` — loads the YAML into `Primitive` objects and resolves `compatible_with`.
- `compose.py` — deterministic, seeded case generation.

## Coverage (as required by the task)
- **G1**: `X-HTTP-Method-Override` / `X-Method-Override` / `X-HTTP-Method` × each target
  method; `_method` query and form body × each method; query op switch
  (`op=freeze`→`close`, unknown, remove, duplicate, case); graphql `operationName` swap
  (delete/unknown/null/duplicate); content-type switch (WAFFLED).
- **G2**: dot-segments (`/../`, `/./`, `%2e%2e`, `%2e`, mixed, fully encoded); `%2F`
  encoded slash; double slash (leading + mid); `;matrix` params; trailing slash; path case
  variants; absolute-form target (same authority, different authority = Host conflict,
  different path); backslash; fragment; null byte `%00`; overlong UTF-8 and fullwidth
  Unicode; prefix rewrite (v1↔v2); whitespace/tab in the request line; duplicate Host;
  `X-Forwarded-Prefix` / `X-Original-URL` / `X-Rewrite-URL`.
- **G3**: inject/alias `X-Verified-Sub`, `X-Forwarded-Client-Cert`, `Client-Cert`,
  `X-Client-Cert`, `X-Verified-Jkt`, `X-Verified-View` (D-B spoof); case variants,
  underscore-vs-dash variants, duplicates.

## Run / test
```
cd binding/harness
python mutator/primitives/build_catalogue.py          # regenerate the YAML (84 primitives)
python -m mutator.compose --depth 1 --stats           # depth-1 cases to stdout
python -m mutator.compose --depth 2 --seed 1337 --pairs-per-op 40 --out cases.jsonl --stats
python -m pytest mutator/tests -q
```
Depth-1 = every primitive applied to every compatible base op (full cross product).
Depth-2 = a seeded, per-op sample of compatible primitive pairs.

## Contract interpretations
- **Depth-2 is sampled, not exhaustive.** The full pair product is large; `compose`
  draws `--pairs-per-op` pairs with a per-op seed (`"{seed}:{op_id}"`), so adding ops never
  perturbs earlier ops' samples and runs are reproducible. Depth-1 remains exhaustive.
- **Compatibility** is expressed by base-op tags + a primitive `applies_to`
  (`requires_tags` or `op_ids`). Op-dispatch primitives apply only to the `action` op,
  graphql swaps only to the graphql op, prefix rewrites only to the matching version.
- **Auth placeholders**: the canonical request carries `Authorization: @@AUTHZ@@` and
  `DPoP: @@PROOF@@`; the runner substitutes a freshly minted header value + proof per case
  so each case gets a unique `jti`. This keeps minting out of case generation (cases are
  static and shareable) while still giving the oracle its correlation key.
- A **baseline (depth-0)** case per op is emitted so the direct ground-truth run and the
  honest-path check have inputs.
