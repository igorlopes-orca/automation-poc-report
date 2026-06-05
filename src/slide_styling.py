"""Per-slide visual styling applied after text tokens are resolved.

Two kinds of rules today, both declarative:

- ``red_paragraphs``: indices of paragraphs whose text should be rendered
  in the red highlight colour. All runs in the paragraph are recoloured.
- ``links``: hyperlinks to inject into specific runs. The target run is
  located either by ``match_text`` (first run whose text contains that
  substring) or by explicit ``run_idx``.

When adding a new slide, add an entry to ``SLIDE_STYLING`` keyed by the
1-based slide number. Pattern for slides 5–10: the first two "Top
Findings" bullets are red.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pptx.dml.color import RGBColor
from pptx.presentation import Presentation as _Prs

RED = RGBColor(0xCC, 0x00, 0x00)


@dataclass
class Link:
    """One hyperlink to apply to a paragraph.

    Exactly one of ``match_text`` or ``run_idx`` should be set. If both
    are set ``run_idx`` wins. If neither is set the link applies to the
    first run.
    """

    paragraph_idx: int
    url: str
    match_text: str | None = None
    run_idx: int | None = None


@dataclass
class SlideStyling:
    red_paragraphs: list[int] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)


# --------------------------------------------------------------------------
# Per-slide rules. Slide numbers are 1-based (what you see in PowerPoint).
# --------------------------------------------------------------------------

SLIDE_STYLING: dict[int, SlideStyling] = {
    # Slide 5 — Vulnerability Mgmt. First two "Top Findings" bullets red.
    5: SlideStyling(red_paragraphs=[5, 6]),
    # Slide 6 — Asset Discovery. First two findings red.
    6: SlideStyling(red_paragraphs=[3, 4]),
    # Slide 7 — Identity & Access. First two findings red.
    7: SlideStyling(red_paragraphs=[6, 7]),
    # Slide 8 — Cloud Compliance. First two of the dynamic list red:
    # total controls + the first framework score.
    8: SlideStyling(red_paragraphs=[5, 6]),
    # Slide 9 — Top Findings. First two findings red.
    9: SlideStyling(red_paragraphs=[2, 3]),
}


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------


def apply_slide_styling(prs: _Prs, styling_by_slide: dict[int, SlideStyling]) -> None:
    """Apply declarative styling to a presentation in place."""
    for slide_num, styling in styling_by_slide.items():
        slide = prs.slides[slide_num - 1]
        tf = _first_text_frame(slide)
        if tf is None:
            continue
        _apply_red(tf, styling.red_paragraphs)
        _apply_links(tf, styling.links)


def _first_text_frame(slide):
    for shape in slide.shapes:
        if shape.has_text_frame:
            return shape.text_frame
    return None


def _apply_red(text_frame, paragraph_indices: list[int]) -> None:
    for idx in paragraph_indices:
        if idx >= len(text_frame.paragraphs):
            continue
        for run in text_frame.paragraphs[idx].runs:
            run.font.color.rgb = RED


def _apply_links(text_frame, links: list[Link]) -> None:
    for link in links:
        if link.paragraph_idx >= len(text_frame.paragraphs):
            continue
        paragraph = text_frame.paragraphs[link.paragraph_idx]
        run = _pick_run(paragraph, link)
        if run is not None:
            run.hyperlink.address = link.url


def _pick_run(paragraph, link: Link):
    runs = paragraph.runs
    if not runs:
        return None
    if link.run_idx is not None:
        return runs[link.run_idx] if link.run_idx < len(runs) else None
    if link.match_text is not None:
        for run in runs:
            if link.match_text in run.text:
                return run
        return None
    return runs[0]
