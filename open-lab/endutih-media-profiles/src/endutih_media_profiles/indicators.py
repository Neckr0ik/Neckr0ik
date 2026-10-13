"""Indicator definitions on ENDUTIH 2025 public microdata.

Every person indicator is a share of **all persons aged 6+ in the cell**
(the ENDUTIH selected-respondent universe). Questions asked only of a
sub-population (e.g. which social networks, asked only of social-media users)
are coded 0 for people outside that sub-population, so all shares in a row
share the same denominator. Household indicators are shares of households.

Coding: ``1`` (yes) → 1, ``2`` (no) → 0. If a *gate* question shows the person
is outside the question's universe the item is 0; any other blank or code
(e.g. 9 = no sabe) is treated as missing and excluded from that indicator's
denominator.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Indicator:
    key: str
    table: str  # "persons" or "households"
    variables: tuple[str, ...]  # any == "1" counts as yes (OR across variables)
    label_en: str
    label_es: str
    gates: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # (var, in-universe code)
    note: str = ""


INTERNET = (("P7_1", "1"),)
SOCIAL = (("P7_1", "1"), ("P7_15", "1"))

PERSON_INDICATORS: tuple[Indicator, ...] = (
    Indicator("internet_user", "persons", ("P7_1",), "Used the internet (last 3 months)", "Usó internet (últimos 3 meses)"),
    Indicator("computer_user", "persons", ("P6_1",), "Used a computer, laptop or tablet (last 3 months)", "Usó computadora, laptop o tablet (últimos 3 meses)"),
    Indicator("cellphone_user", "persons", ("P8_3",), "Used a mobile phone (last 3 months)", "Usó celular (últimos 3 meses)"),
    Indicator("owns_cellphone", "persons", ("P8_1",), "Has a mobile phone", "Dispone de celular"),
    Indicator("internet_via_smartphone", "persons", ("P7_6_4",), "Went online with a smartphone", "Se conectó a internet con smartphone", INTERNET),
    Indicator("internet_via_smart_tv", "persons", ("P7_6_5",), "Went online with a smart TV or TV-connected device", "Se conectó a internet con Smart TV", INTERNET),
    Indicator("social_media_user", "persons", ("P7_15",), "Used social media (last 3 months)", "Usó redes sociales (últimos 3 meses)", INTERNET),
    Indicator("facebook", "persons", ("P7_16_1",), "Uses Facebook", "Usa Facebook", SOCIAL),
    Indicator("whatsapp", "persons", ("P7_16_6",), "Uses WhatsApp (as social network)", "Usa WhatsApp (como red social)", SOCIAL),
    Indicator("youtube", "persons", ("P7_16_7",), "Uses YouTube (as social network)", "Usa YouTube (como red social)", SOCIAL),
    Indicator("instagram", "persons", ("P7_16_3",), "Uses Instagram", "Usa Instagram", SOCIAL),
    Indicator("tiktok", "persons", ("P7_16_10",), "Uses TikTok", "Usa TikTok", SOCIAL),
    Indicator("x_twitter", "persons", ("P7_16_2",), "Uses X (Twitter)", "Usa X (Twitter)", SOCIAL),
    Indicator("paid_video_streaming", "persons", ("P7_13_2",), "Watched paid video online (Netflix-type, last 3 months)", "Vio audiovisuales de pago en internet", INTERNET),
    Indicator("free_online_video", "persons", ("P7_13_3",), "Watched free video online (YouTube-type)", "Vio audiovisuales gratuitos en internet", INTERNET),
    Indicator("free_music_streaming", "persons", ("P7_13_4",), "Listened to free music online (not AM/FM)", "Escuchó música gratis en internet (no AM/FM)", INTERNET),
    Indicator("online_radio", "persons", ("P7_13_6",), "Accessed AM/FM radio content online", "Accedió a radio AM/FM por internet", INTERNET),
    Indicator("online_tv", "persons", ("P7_13_7",), "Watched broadcast TV channels online", "Vio TV abierta por internet", INTERNET),
    Indicator("online_reading", "persons", ("P7_13_1",), "Read newspapers, magazines or books online", "Leyó periódicos, revistas o libros en internet", INTERNET),
    Indicator("online_shopping_12m", "persons", ("P7_21",), "Bought online (last 12 months)", "Compró por internet (últimos 12 meses)", INTERNET),
    Indicator("radio_last_week", "persons", ("P10_1",), "Listened to the radio last week (any device)", "Escuchó la radio la semana pasada"),
    Indicator("open_tv_last_week", "persons", ("P10_7",), "Watched broadcast (open) TV last week", "Vio televisión abierta la semana pasada"),
)

HOUSEHOLD_INDICATORS: tuple[Indicator, ...] = (
    Indicator("hh_internet", "households", ("P4_4",), "Household has internet", "Hogar con internet"),
    Indicator("hh_computer", "households", ("P4_2_1", "P4_2_2", "P4_2_3"), "Household has a desktop, laptop or tablet", "Hogar con computadora, laptop o tablet"),
    Indicator("hh_radio", "households", ("P4_1_1",), "Household has a radio", "Hogar con radio"),
    Indicator("hh_flat_tv", "households", ("P4_1_4",), "Household has a flat-screen TV", "Hogar con pantalla plana"),
    Indicator("hh_smart_tv", "households", ("SMART_TV",), "Household has at least one smart TV", "Hogar con al menos una Smart TV",
              note="Derived: P4_1_4_2 (number of smart flat screens) >= 1; 0 if no flat screen; 99 = missing."),
    Indicator("hh_pay_tv", "households", ("P5_1",), "Household has pay TV", "Hogar con TV de paga"),
    Indicator("hh_streaming_service", "households", ("P5_6",), "Household has a streaming service (Netflix, Spotify, …)", "Hogar con servicio de streaming"),
    Indicator("hh_fixed_phone", "households", ("P5_5",), "Household has a fixed telephone line", "Hogar con línea telefónica fija"),
)

ALL_INDICATORS = PERSON_INDICATORS + HOUSEHOLD_INDICATORS
BY_KEY = {i.key: i for i in ALL_INDICATORS}
