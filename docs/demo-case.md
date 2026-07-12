# Lab Validation

Use an authorized Windows VM, public training image, or course-provided memory image. Do not commit real memory dumps to GitHub.

Recommended validation:

1. Run `ramscope doctor`.
2. Run `ramscope validate --input <memory.raw>`.
3. Run Volatility `windows.info` manually if symbols/profile support is uncertain.
4. Run `ramscope analyze` with and without external YARA rules.
5. Review raw plugin errors before relying on report conclusions.
