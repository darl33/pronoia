"""Evaluation harness (DESIGN.md §7).

Nothing here writes to the database. It reads reference data so the guardrails
it exercises are the real ones, and runs against the fixtures in `gold/` -- an
eval must not be able to contaminate the dataset it is measuring.
"""
