"""Mutation-feedback fuzzing engine for Soul Protocol.

Implements coverage-guided fuzzing with:
  - Mutation-based input generation (Soul-aware)
  - Coverage feedback loop (branch/line tracking)
  - Invariant property testing
  - Corpus evolution (keep interesting inputs)
  - Adaptive mutation weight adjustment
"""
