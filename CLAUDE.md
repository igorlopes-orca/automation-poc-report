# CLAUDE.md — project notes for Claude

## What this project does

CLI that produces an Orca POC recap `.pptx` for a single tenant. MVP
scope is numbers only — screenshots are intentionally deferred.

- `generate.py --lang pt|es` orchestrates the run.
- `src/orca_client.py` pulls numbers from the Orca serving-layer API.
- `src/pptx_filler.py` fills `{{metrics.*}}` tokens in
  `templates/poc_report_{pt,es}.pptx`.
- `src/slide_styling.py` applies declarative colour/hyperlink rules per
  slide after text substitution.

## Development best practices

### Reuse the serving-layer body; only the query filter changes

Nearly every metric we pull from Orca is a count from
`POST /api/serving-layer/query`. The request body is the same every time
— same envelope, same `limit`, same `select`, same `get_results_and_count`.
The only thing that varies between metrics is the `query.with` filter.

When adding a new metric:

1. Prefer `OrcaClient.count(model, with_filter=<dsl>)` — it already owns
   the full envelope. Don't reintroduce the envelope elsewhere.
2. Build the `with_filter` from the small DSL helpers in
   `orca_client.py` (`_and`, `_or`, `_in`, `_eq`, `_has`). Keep the filter
   side of the codebase composable.
3. If the filter shape doesn't yet have a helper (e.g. a nested `has` on a
   related model), add a minimal helper — don't inline a one-off dict that
   diverges from the rest.

### One metric per method on `OrcaClient`

Each slide has a grouping method like `get_vulnerability_metrics()` that
returns a dataclass. Add new counts as fields on that dataclass, not as
free-floating methods. That keeps `generate.py` simple (one fetch per
slide, one display-format per slide).

### Template edits stay scripted

`scripts/tokenize_*.py` contains the one-time template surgery. If a
token set changes, update the script and re-run it, rather than editing
`.pptx` files by hand in PowerPoint — PowerPoint will silently split
runs and reformat paragraphs on save.

### Slide-level styling is declarative, not baked into the template

Colour highlights (e.g. red on the two most-urgent bullets) and
hyperlinks are applied at fill time via `src/slide_styling.py`. The
templates we manage (slides 5–7 today) have no baked-in colours or
hyperlinks — `scripts/tokenize_templates.py` strips them on every
re-tokenise so the styler is always the source of truth.

To add a rule for a new slide, add an entry to the `SLIDE_STYLING` dict:

```python
SLIDE_STYLING[6] = SlideStyling(
    red_paragraphs=[5, 6],
    links=[Link(paragraph_idx=5, url="https://app.orcasecurity.io/...",
                match_text="link")],
)
```

Convention for POC slides 5–10: the first two "Top Findings" bullets
are red.

### Tokens might span multiple runs

PowerPoint frequently splits `{{metrics.vuln.total}}` across several
runs (`{{`, `metrics.vuln.total`, `}}`). The filler already handles
this by collapsing each token-bearing paragraph into its first run.
Don't reintroduce per-run substitution.

### Testing without the API

`src/pptx_filler.py` is pure; smoke-test it with a fake metrics dict
(see the smoke tests used during development). Use `--dry-run` on
`generate.py` to iterate on query correctness without writing a
`.pptx`.
