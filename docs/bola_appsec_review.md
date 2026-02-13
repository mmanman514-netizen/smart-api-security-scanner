# BOLA/IDOR AppSec Architecture Review (Current Scope)

This document records a strict, scope-limited review of the current BOLA/IDOR scanner behavior and wiring.

## Critical execution and wiring risks

1. `main.py` imports `utils.report_generator` and `utils.logging_setup`, but these modules are not present in this repository. This can prevent scanner startup in normal execution paths.
2. `BOLAScanner.scan()` is called directly without entering the scanner async context (`__aenter__`), leaving `self.session` uninitialized when `_make_request()` runs.
3. The default `config.json` is not valid JSON (contains `//` comments) while `ConfigLoader.load()` uses strict `json.load()` for `.json` files.

## BOLA logic risks

4. Detection logic is similarity-based but does not verify ownership linkage (despite requiring owner context semantically).
5. ID discovery for endpoints with placeholders other than `{id}` is incomplete and often falls back to static/default IDs.
6. Default IDs are appended regardless of resource regex validation rules.
7. Response similarity confidence stored in findings is boolean, not a numeric score.

## Safety and operational risks

8. Runtime request pacing semantics are inconsistent with the config key `requests_per_second`.
9. Request errors are often collapsed into status `0` responses and treated as non-vulnerable, suppressing meaningful diagnostics.
10. Empty `requirements.txt` makes environment reproducibility and runtime setup unreliable.

## Misleading or dead paths

11. `core/orchestrator.py` references `time` without importing it.
12. `models/api_resource.py` imports `Enum` from `typing` instead of `enum`, causing import-time failure.
13. `scanner/base.py` is a placeholder/miswired reference (`from scanners.base import BaseScanner`) and does not align with repository paths.
