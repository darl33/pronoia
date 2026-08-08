"""Evaluation harness (DESIGN.md §7).

Nothing in here writes to the database. The harness reads reference data
(attack_technique, threat_actor) so the guardrails it exercises are the real
ones, and runs the extraction against gold-set fixtures held in `gold/` -- it
never touches raw_document or report. An eval run must not be able to
contaminate the dataset it is measuring.
"""
