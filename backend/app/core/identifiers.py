"""Vergleich von Benutzer- und Gruppennamen wie in der Datenbank.

Die RADIUS-Tabellen verwenden die Standardkollation von MariaDB; sie vergleicht
ohne Ruecksicht auf Gross- und Kleinschreibung. Wer im Anwendungscode mit
exakten Zeichenketten arbeitet - Sperrschluessel, Dublettenerkennung,
Zusammenfassen von Mitgliedschaften - bewertet ``Staff`` und ``staff`` deshalb
als verschieden, waehrend die Datenbank dieselbe Zeile meint.
"""

from __future__ import annotations

import unicodedata


def is_case_variant(old: str, new: str) -> bool:
    """Ob sich zwei Namen ausschliesslich in der Gross-/Kleinschreibung
    unterscheiden.

    Bewusst ohne ``fold``: das entfernt auch Leerzeichen und Akzente. ``" Staff"``
    und ``"Staff"`` sind fuer die Datenbank zwei Namen - als
    Schreibweisenaenderung behandelt wuerden beim Umbenennen zwei Gruppen
    zusammengefuehrt.
    """
    return old != new and old.casefold() == new.casefold()


def fold(name: str) -> str:
    """Vergleichsform eines Bezeichners.

    Nachgebildet werden beide Eigenschaften der Standardkollation: sie
    unterscheidet weder Gross- und Kleinschreibung noch Akzente. ``cafe`` und
    ``cafe`` mit Accent aigu bezeichnen dort dieselbe Zeile; ein reiner
    ``casefold``-Vergleich ergaebe zwei verschiedene Sperrschluessel und beide
    Aufrufer liefen gleichzeitig durch die Sperre.

    Die Richtung ist bewusst grosszuegig: fasst diese Form zwei Namen zusammen,
    die die Datenbank unterscheidet, wird lediglich mehr serialisiert. Der
    umgekehrte Fehler waere der gefaehrliche.
    """
    # NFKD zerlegt Zeichen in Grundzeichen und kombinierende Marken; die Marken
    # (Kategorie ``Mn``) entfallen, wie beim akzentunempfindlichen Vergleich.
    decomposed = unicodedata.normalize("NFKD", name.strip())
    without_marks = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return without_marks.casefold()
