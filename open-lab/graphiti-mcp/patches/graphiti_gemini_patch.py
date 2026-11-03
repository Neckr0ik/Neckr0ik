"""Parche de arranque para graphiti-core (lo carga zz_graphiti_gemini_patch.pth al arrancar Python).

graphiti-core fija como modelo "small" de Gemini y como reranker `gemini-2.5-flash-lite`, que Google ya no
ofrece a usuarios nuevos (404 NOT_FOUND), y no deja configurarlos. Aqui se sustituyen al arrancar.
Variables: GEMINI_SMALL_MODEL y GEMINI_RERANKER_MODEL (por defecto gemini-3.5-flash-lite).
"""
import os

try:
    import graphiti_core.llm_client.gemini_client as _g
    import graphiti_core.cross_encoder.gemini_reranker_client as _r

    _g.DEFAULT_SMALL_MODEL = os.getenv("GEMINI_SMALL_MODEL", "gemini-3.5-flash-lite")
    _r.DEFAULT_MODEL = os.getenv("GEMINI_RERANKER_MODEL", "gemini-3.5-flash-lite")
except Exception:  # nunca impedir el arranque
    pass
