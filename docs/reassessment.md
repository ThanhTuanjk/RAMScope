# Reassessment

`ramscope reassess --case C:\Cases\CASE001 --format html` re-runs normalization, correlation, scoring, and report generation from hash-verified raw artifacts. It does not execute Volatility again and does not modify the original case artifacts.

Use reassessment when the analysis engine or report format changes. Preserve the original case directory as evidence and review the reassessment coverage for unresolved or timed-out plugins.

