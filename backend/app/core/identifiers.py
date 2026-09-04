"""Vergleich von Benutzer- und Gruppennamen wie in der Datenbank.

Die RADIUS-Tabellen verwenden die Standardkollation von MariaDB; sie vergleicht
ohne Ruecksicht auf Gross- und Kleinschreibung. Wer im Anwendungscode mit
exakten Zeichenketten arbeitet - Sperrschluessel, Dublettenerkennung,
Zusammenfassen von Mitgliedschaften - bewertet ``Staff`` und ``staff`` deshalb
als verschieden, waehrend die Datenbank dieselbe Zeile meint.
"""

from __future__ import annotations


def fold(name: str) -> str:
    """Vergleichsform eines Bezeichners.

    ``casefold`` deckt die hier vorkommenden Namen ab (Kennungen, Gruppennamen,
    MAC-Adressen). Eine vollstaendige Nachbildung der Kollation - etwa deren
    Behandlung von Akzenten - waere ohne die Datenbank nicht moeglich; die
    verbleibenden Faelle werden dort ueber die Existenzpruefung erkannt.
    """
    return name.strip().casefold()
