# Contributing

Contributions should improve defensive value, correctness, reproducibility, or documentation.

1. Explain the threat model and intended operator.
2. Keep defaults read-only and fail closed on invalid input.
3. Add deterministic tests; CI must not depend on live services.
4. Preserve provenance and distinguish observations from heuristic assessments.
5. Never log, print, or persist raw secret values.
6. Do not add exploit execution, stealth, persistence, credential stuffing, or unauthorized scanning.
7. Run `ruff check .` and `pytest`.

Document new dependencies, network destinations, filesystem access, and security assumptions. Keep pull requests focused.