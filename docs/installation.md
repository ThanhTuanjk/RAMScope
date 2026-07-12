# Installation

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[full]"
```

Optional Windows tools:

- Install ClamAV if you want `clamscan` results.
- Install Detect-It-Easy if you want `diec` packer/compiler hints.

Verify each optional scanner:

```powershell
floss --version
capa --version
clamscan --version
diec --version
python -c "import pefile; print(pefile.__version__)"
```

Run:

```powershell
ramscope doctor
```

Missing optional tools are reported as unavailable and do not block analysis.

Keep Volatility3 and `yara-python` in the same virtual environment. This is important because `windows.vadyarascan` may be unavailable when the Volatility environment cannot import YARA.

For a Windows 10 malware lab, use a disposable VM snapshot, host-only or isolated networking, no shared clipboard/folders, and transfer only the RAM image and case output after the specimen is stopped. RAMScope analyzes an acquired image; it does not safely execute or contain malware.
