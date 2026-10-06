# Phase 15 - Evidence verification, contradictions and reports

## 1. Purpose
Turn findings into a report a professional can rely on: every statement checked against its
evidence, disagreements between sources surfaced and explained instead of silently resolved,
unknowns labelled as unknown, and every figure traceable to a source with full provenance. The
report is exportable as Markdown, JSON, CSV and PDF without carrying anything executable or
clickable that a hostile page could have planted.

## 2. Architecture
```
... analyze ──► verify ──► contradictions ──► report                (checkpointed stages)

verify          load_job_evidence (findings + citations + chunks + provenance, under RLS)
                code: quote present? every figure in the evidence?  ── ceiling
                VERIFIER agent (claim + cited chunks only)          ── may lower, never raise
                → support = supported | partial | unsupported | contradicted
                → unsupported facts become hypotheses (confidence ≤ 0.3)

contradictions  code: pairs of included findings, different sources, shared subject,
                      different figures or polarity                  ── candidates (≤ 20)
                CONTRADICTION_JUDGE agent: real conflict? attribute? explanation? preference?
                code: keep a preference only if its reason is true (newer date, ≥ 0.2 more
                      reliable source); otherwise "neither" + the uncertainty is presented

report          REPORTER agent: summary, narratives (F-refs), recommendations, limitations
                code: drop sentences with figures not in the evidence, sentences resting only
                      on rejected findings, recommendations without findings; defang URLs
                CRITIC agent (advisory rubric) ─► one revision if weak and budget allows
                code: assemble ReportDocument (argus.report/1): sections (answered |
                      "Insufficient evidence."), findings, contradictions, recommendations
                      (evidence | gap | contradiction), limitations, sources with provenance,
                      methodology, quality ──► research_reports (+ rendered Markdown)

GET .../report                    canonical JSON          reports:read, origins, clearance
GET .../report/export?format=     markdown | json | csv | pdf   reports:export, audited, rate-limited
GET .../contradictions            per-viewer filtered
```

## 3. Why this design
* **Code decides what code can decide.** Whether a quoted sentence is in a chunk, whether a figure
  appears in the evidence, whether a source is newer - these are facts, checked mechanically. A
  model is used for what needs judgement (entailment, whether two statements really conflict,
  prose), and its output is checked again by code.
* **Models may only lower trust.** A verifier verdict can downgrade a finding the code accepted,
  never upgrade one it rejected; a preference for one side of a contradiction survives only if
  its stated reason holds in the metadata; draft prose is filtered, never extended.
* **One canonical report.** All exports render the same versioned JSON document, so the PDF can
  never say something the JSON does not.
* **fpdf2** generates PDFs in pure Python, without a browser engine or JavaScript support; the
  container ships DejaVu Sans so non-Latin scripts (Persian, Arabic, Cyrillic...) render.

## 4. Security
* **Hallucination (P5).** Figures in a statement must appear in its cited evidence; unsupported
  facts are downgraded and excluded from the report; sentences in the report's prose that state
  figures absent from the evidence, or rest only on rejected findings, are removed and counted
  in the quality score; "Insufficient evidence." replaces guesses.
* **Injected claims (P3).** Only supported or partially supported findings reach the report;
  rejected statements are counted, never printed, so an injected sentence cannot reappear in an
  appendix. Contradictions keep both values visible.
* **Exfiltration through rendered output (P2).** URLs inside any source-derived text are defanged
  (`hxxps://`); Markdown escapes every structural character, so text cannot become a link, an
  image or HTML; only collected `http(s)` source URLs are linked, in the appendix; CSV cells that
  a spreadsheet would execute (`= + - @`, tab, CR) are neutralised; PDFs contain no scripts.
* **Confidentiality.** A report records the highest classification it rests on; a viewer below it
  cannot open or export it (a summary blends every finding, so it cannot be filtered per
  statement). Contradictions involving a withheld finding are listed without their content.
  Reading needs `reports:read`, exporting `reports:export`, plus read access to the job's
  origins.
* **Accountability.** Every export is audited (`report.exported`: format, version, size) and
  rate-limited per principal; the methodology section names the models, prompt versions, human
  approvals and cost behind the report.
* **Every stage re-authorises the job's creator** before spending budget (P9), and all four
  agents run under the phase 12-14 runtime: no tools, limits, kill switches, recorded runs.

## 5. Files
`modules/research/{evidence,verification,contradictions,reporting,report_model,exports,results}.py`,
`modules/research/models.py` (`support`, `ResearchContradiction`, `ResearchReport`),
`prompts/{verification.entailment,verification.contradictions,report.compose,report.critic}/v1.yaml`,
`apps/api/v1/research.py` (contradictions, report, export), `core/config.py` (`ReportSettings`),
`Dockerfile` (fonts), `migrations/versions/0010_verification_and_reports.py`.

## 6. Code worth reading
* `verification.py::mechanical_ceiling` and `combine` - the one-way ratchet on trust.
* `contradictions.py::justified` - why "prefer the newer source" must be *true* to count.
* `reporting.py::check_draft` - code that only ever removes model output.
* `exports.py::md`, `csv_cell`, `safe_link` - treating every source-derived string as hostile.

## 7. Tests
* `tests/unit/test_reporting_units.py` - figure normalisation, negation, defanging, verdict
  ceilings and ratchet, confidence caps, the offline verifier, contradiction candidates and
  justification (including a source title that lies about its date), draft checks, the offline
  reporter and critic, assembly (unknowns, gap recommendations, confidence), JSON round trip,
  Markdown/CSV/PDF safety, PDF with a Unicode font.
* `tests/integration/test_reports.py` - a hybrid job's report with provenance and an unanswered
  question; two sources disagreeing on a figure, reported with the newer one preferred and both
  values shown; a stand-in model that invents a figure, writes ungrounded prose and reviews
  harshly - nothing invented reaches the report, and one revision happens; exports that stay
  inert, are audited and need `reports:export`; restricted reports closed to lower clearance.

## 8. Common mistakes avoided
Asking a model whether its own citation is right; letting a model pick between conflicting
values; showing rejected claims "for transparency"; filtering citations but not the summary;
rendering source text as Markdown or HTML; linking every URL a page contains; trusting CSV
consumers not to evaluate formulas; generating PDFs with a headless browser.

## 9. Scalability
Verification and contradiction judgements are batched (8 claims, 10 pairs per call); candidate
pairs are capped at 20 per job; evidence is loaded once per stage with one joined query; reports
are stored rendered, so reading one is a single row; PDF rendering is per request, CPU-bound and
rate-limited (move it to the worker queue if exports grow large).

## 10. Next phases
Phase 16 evaluates verification, contradiction recall and report grounding on a fixed corpus with
known traps, and gates prompt changes on the scores. Phase 17 reuses the report pipeline for
monitoring digests; phase 18 links findings to entities in the knowledge graph.

## 11. Acceptance criteria
- [x] Every finding gets a verdict; figures absent from the evidence can never be "supported".
- [x] Only supported or partially supported findings reach the report; unknowns say
  "Insufficient evidence.".
- [x] Disagreeing sources are detected, explained, and both values are shown; a value is
  preferred only for a verifiable reason.
- [x] Report prose cannot state figures, or repeat claims, that the evidence does not support.
- [x] Reports carry source provenance (URL, type, retrieval and publication dates, content hash,
  extraction method, reliability) and the methodology behind them.
- [x] Markdown, JSON, CSV and PDF exports are inert, audited, rate-limited and permissioned.
- [x] Reports resting on restricted evidence are closed to viewers below that clearance.

## 12. How the specification maps to this design
| Specification | Here |
|---|---|
| §24 Source provenance | `ReportSource`: source id, URL, type, retrieved/published, content hash, document id, author, publisher, extraction method, reliability |
| §25 Fact / inference / hypothesis / opinion / unknown | finding kinds + support level; unknown = section status `insufficient_evidence` |
| §25 "Insufficient evidence." | exact wording for unanswered questions |
| §26 Contradiction → dates → reliability → explanation → uncertainty | `candidate_pairs` → `justified` → `uncertainty` |
| §54 Report sections and formats | executive summary, analysis, findings, evidence, citations, confidence, contradictions, recommendations, appendices, source list; Markdown, PDF, JSON, CSV |
