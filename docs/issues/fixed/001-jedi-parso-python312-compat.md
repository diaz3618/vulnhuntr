# 001 — Python 3.12/3.13: Jedi and Parso Compatibility

**Status:** Fixed  
**Date Identified:** 2026-02-05  
**Date Fixed:** 2026-02-05  
**Commit:** `abcd8ad`  
**Affected Component:** `symbol_finder.py`, dependency resolution  

## Symptoms

Running vulnhuntr on Python 3.12 or 3.13 produced import errors or silent symbol resolution failures. Jedi could not parse Python files correctly because Parso lacked grammar definitions for newer Python versions.

Typical errors:
```
ParserSyntaxError: invalid syntax
AttributeError: module 'parso' has no attribute...
```

Or more subtly: Jedi symbol lookups returned no results for valid symbols, causing the iterative context expansion loop to stall.

## Root Cause

The original `requirements.txt` pinned older versions of `jedi` and `parso` that only had grammar definitions for Python up to 3.10/3.11:

- `jedi==0.18.x` — limited grammar support
- `parso==0.8.3` — no Python 3.12+ grammar files

Parso ships bundled grammar files (`grammar3XX.txt`) for each supported Python minor version. When running on Python 3.12, Parso fell back to the closest available grammar, which caused incorrect AST parsing.

## Fix

Upgraded both packages to versions with Python 3.12–3.13 support:

```bash
pip install --upgrade jedi>=0.19.2 parso>=0.8.5
```

Updated `requirements.txt` and `pyproject.toml` to reflect the new minimum versions:

```toml
jedi = "^0.19.2"
parso = "^0.8.5"
```

## Verification

```bash
python -c "import jedi; print(jedi.__version__)"   # 0.19.2+
python -c "import parso; print(parso.__version__)"  # 0.8.5+
python --version                                     # 3.12.x or 3.13.x
python -m vulnhuntr --help                           # Smoke test
```

## Notes

- Python 3.14+ is still **not supported** — Jedi/Parso do not yet ship grammar files for it.
- Python 3.10–3.13 is the supported range. This is enforced in `pyproject.toml`.
- If Jedi or Parso release a version supporting 3.14, update the constraints accordingly.
