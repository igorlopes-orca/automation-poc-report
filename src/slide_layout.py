"""Per-slide structural constants shared by template prep and runtime fill.

``BULLET_START_IDX[N]`` is the paragraph index where the metric/bullet
section begins on slide N. Used both by ``scripts/tokenize_templates``
(to know which paragraphs to overwrite or clone) and by
``src/pptx_filler`` (to know where to inject dynamic bullet blocks).
Keeping it in one place prevents the two from drifting.
"""

from __future__ import annotations

BULLET_START_IDX: dict[int, int] = {
    5: 5,  # Vulnerability Mgmt — bullets follow "Top Findings:" header
    6: 3,  # Asset Discovery — bullets follow "Inventario" header
    7: 6,  # Identity & Access — bullets follow "Top Findings:" header (P5)
    8: 5,  # Cloud Compliance — bullets follow "Customer Compliance:" header
    9: 2,  # Top Findings — bullets follow "Alertas de maior risco" subtitle
}
