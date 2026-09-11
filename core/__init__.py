"""BARE core: sandbox, orchestration, analyzers, correlation, LLM layer.

Deliberately free of imports. Analyzer containers import ``core.rules`` with
only PyYAML installed, and any import here would be dragged in with it.
"""

__version__ = "0.0.1"
__all__ = ["__version__"]
