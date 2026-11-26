"""Dependency-free constants shared by the CLI and the authority."""

NODES = {"node-a": "frontend", "node-b": "billing", "node-c": "secrets"}

# One documented timing range for both detectors (seconds).
MAX_CLOCK_OFFSET = 120      # largest trusted source-clock offset that is corrected, not flagged
MAX_LATENESS = 30           # largest corrected collector delay inside the reorder buffer
MAX_NEGATIVE_SKEW = 1.0     # corrected delay may dip this far below zero (residual offset error)
