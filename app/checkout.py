"""Minimal checkout example used to verify the PR review workflow."""


def calculate_line_total(unit_price: float, quantity: int) -> float:
    """Return the amount charged for one checkout line."""
    return unit_price * quantity
