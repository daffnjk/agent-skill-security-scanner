# Candidate rejection and conservative ablation protocol

The first frozen candidate (`ec71099a15caf25223931698a6fa487344ba9fb4`, patch SHA-256 recorded in CANDIDATE_FREEZE.json) reduced false positives, but lost one strict true positive on ATR and three on SkillsBench-1650. It is NOT accepted as a recall-preserving improvement. Its complete results must remain in the final report, including screening and runtime regressions.

The original holdouts have now been opened. Every subsequent result on these three sources is **regression/selection evidence, not blind holdout evidence**. Do not tune on individual test payloads or identifiers.

Before running any ablation outcomes, define four mechanical alternatives:

1. `conservative`: the first candidate, but restore the complete baseline conditionalOrDelayedPayload function. This tests whether the narrowed delayed-payload requirement removed useful recall.
2. `lexical`: baseline detector plus lexical boundaries in the six originally modified helpers and removal of bare raw/gist/paste URL strings from the MCP shell-command predicate. No new proximity windows, narrowed payload requirements, Markdown parser, or fenced IR hook.
3. `structural`: baseline plus lexical boundaries only in ClickFix and startup helpers, the bare-URL MCP correction, and the new Markdown parser/fenced IR hook. No narrowed delayed payload, persistence-launch requirement, transfer requirement, or proximity windows.
4. `minimal`: baseline plus lexical boundaries only in ClickFix and startup helpers and removal of bare raw/gist/paste URLs from the MCP shell-command predicate. No other behavior changes.

Select only alternatives that do not lower true positives or increase false positives, per source, in BOTH strict (malicious) and screening (malicious|suspicious) modes, and do not worsen completeness. Among eligible alternatives, prefer the largest unweighted mean per-source F2 gain; break ties by fewer behavior changes. Never select per-sample overrides. If none qualify, report failure rather than lowering acceptance criteria.

After selection, freeze the source again BEFORE running another external source. Use the checksum-frozen SkillTrustBench snapshot (upstream f90517b7058fdcfea89af114c069fbf973f42bc7, archive SHA-256 a1970087675a6991788c2624eb6101b72445a7c56b3e1720bd2b97f0add6622f). Respect CC-BY-NC-SA-4.0 and upstream attribution. Preserve malicious/suspicious/normal labels; only malicious versus normal supports binary evaluation. The size and layout will be checked without viewing scanner outcomes. Choose an input-only, deterministic, source-isolated validation subset, freeze its IDs/hashes, and do not modify the selected detector after its outcomes are opened. Exclude exact/near-duplicate and available repository overlap with the entire 2,495-record selection corpus, and report excluded counts. Public data may have been seen by previous scanner authors; this is not a historically pristine benchmark or a production prevalence estimate.
