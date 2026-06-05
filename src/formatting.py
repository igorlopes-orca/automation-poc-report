from __future__ import annotations


def format_count(value: int, lang: str) -> str:
    """Format an integer count for display in the deck.

    Both PT and ES use '.' as the thousands separator in prose
    (e.g. 518.865). Numbers under 10k are rendered plainly.
    """
    if value < 10_000:
        return str(value)
    return f"{value:,}".replace(",", ".")


def format_percent(value: float, lang: str) -> str:
    """Render a percentage without trailing zeros."""
    if value == int(value):
        return f"{int(value)}%"
    return f"{value:g}%"
