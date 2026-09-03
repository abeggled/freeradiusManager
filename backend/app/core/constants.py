"""Gemeinsame Grenzwerte, die Schemas und Dienste teilen."""

from __future__ import annotations

MIN_PASSWORD_LENGTH = 12
"""Mindestlaenge fuer Manager-Passwoerter (FR-10).

Gilt auch fuer den Bootstrap-Administrator aus der Umgebung; sonst waere ein
Platzhalter dort ein vollwertiger Zugang mit ratbarem Passwort.
"""
