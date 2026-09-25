"""
The checks.

Each one is a small class with two methods: ``applies``, which says whether an
insertion point is worth spending requests on, and ``run``, which attacks it
and returns confirmed findings. They share nothing but the oracles, so a new
check is a new file and one line in the engine's registry — and a check that
cannot prove what it found returns nothing rather than a maybe.
"""
