# -*- coding: utf-8 -*-
"""Překlady: zdrojové texty jsou anglicky, čeština je v `i18n/cs.po`. Jazyk určí přihlášený uživatel,
takže AI dostane popisy nástrojů a hlášky v jeho jazyce.

Texty na úrovni modulu (popisy nástrojů, hlášky z funkcí bez prostředí) jsou `_lt(...)` a přeloží
se až při použití přes `localize` nebo `error_text`.
"""
from odoo.tools.translate import LazyGettext


def localize(env, value):
    """`_lt` texty → text v jazyce prostředí, i uvnitř slovníků a seznamů (schéma nástrojů)."""
    if isinstance(value, LazyGettext):
        return env._(value)
    if isinstance(value, dict):
        return {key: localize(env, item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [localize(env, item) for item in value]
    return value


def in_english(value) -> str:
    """Text bez překladu (logy, OAuth odpovědi pro klienty, `str()` výjimek)."""
    return value._translate("en_US") if isinstance(value, LazyGettext) else str(value)


def error_text(env, error: Exception) -> str:
    """Zpráva výjimky v jazyce prostředí. Výjimky z `lib` nesou v `args` texty `_lt`, víc textů se spojí."""
    if not any(isinstance(arg, LazyGettext) for arg in error.args):
        return str(error)
    return " ".join(dict.fromkeys(str(localize(env, arg)) for arg in error.args))
