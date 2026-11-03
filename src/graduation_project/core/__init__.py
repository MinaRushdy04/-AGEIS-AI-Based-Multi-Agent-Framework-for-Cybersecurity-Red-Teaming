"""Core engine: the deterministic orchestration layer.

Nothing in this package is LLM-backed. It owns the engagement state, the
scope control (RoE), persistence, and the scheduling loop. The language-model
work lives in `graduation_project.agents`.
"""
