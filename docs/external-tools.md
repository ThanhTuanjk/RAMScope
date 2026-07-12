# External Tools

RAMScope can use optional tools when they are installed. They are enrichment inputs, not proof by themselves.

Check availability with `ramscope doctor`. Common commands are:

```powershell
floss --version
capa --version
clamscan --version
diec --version
python -c "import pefile; print(pefile.__version__)"
```

ClamAV and Detect It Easy are system applications and are intentionally not pip dependencies. A missing tool is recorded as unavailable and does not invalidate the Volatility analysis.

