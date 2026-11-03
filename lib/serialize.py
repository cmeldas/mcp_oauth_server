# -*- coding: utf-8 -*-
"""Převod hodnot polí Odoo na JSON pro odpovědi nástrojů a zpět z JSON na hodnoty pro zápis."""
import datetime
import json

from odoo.fields import Command
from odoo.tools.mail import html2plaintext
from odoo.tools.translate import LazyTranslate

_lt = LazyTranslate(__name__)

TEXT_LIMIT = 2000
X2MANY_LIMIT = 50
BINARY_TYPES = ("binary", "image")
SKIPPED_TYPES = ("properties", "properties_definition")


def truncate(env, text: str | None, limit: int = TEXT_LIMIT) -> str | None:
    if not text:
        return text or None
    if len(text) <= limit:
        return text
    return text[:limit] + "… " + env._("(truncated, %s characters in total)", len(text))


def format_value(env, field, value):
    """Hodnota z `read()` → JSON. `field` je objekt pole z `Model._fields`."""
    ftype = field.type
    if ftype == "boolean":
        return bool(value)
    if ftype in ("integer", "float", "monetary"):
        return value or 0
    if value is False or value is None:
        return None
    if ftype == "many2one":
        return {"id": value[0], "name": value[1]} if isinstance(value, (list, tuple)) else value
    if ftype in ("one2many", "many2many"):
        ids = list(value)
        return ids if len(ids) <= X2MANY_LIMIT else {"ids": ids[:X2MANY_LIMIT], "count": len(ids)}
    if ftype == "html":
        return truncate(env, html2plaintext(value))
    if ftype in ("char", "text"):
        return truncate(env, value)
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if ftype == "json":
        text = json.dumps(value, ensure_ascii=False, default=str)
        return value if len(text) <= TEXT_LIMIT else truncate(env, text)
    return value


def format_records(records, field_names: list[str], base_url: str) -> list[dict]:
    """Načte záznamy jako přihlášený uživatel. Binární pole se nečtou, vrací se jen odkaz."""
    fields_map = records._fields
    plain = [f for f in field_names if fields_map[f].type not in BINARY_TYPES]
    binary = [f for f in field_names if fields_map[f].type in BINARY_TYPES]
    rows = records.read(plain) if plain else [{"id": rid} for rid in records.ids]
    result = []
    for row in rows:
        item = {"id": row["id"]}
        for name in plain:
            if name != "id":
                item[name] = format_value(records.env, fields_map[name], row.get(name))
        for name in binary:
            item[name] = {
                "binary": True,
                "url": f"{base_url}/web/image/{records._name}/{row['id']}/{name}"
                if fields_map[name].type == "image" else None,
            }
        result.append(item)
    return result


def normalize_values(model, values: dict) -> dict:
    """Hodnoty od AI klienta → hodnoty pro `create`/`write`.

    - many2one: `{"id": 5}` nebo `[5, "Název"]` → `5`;
    - many2many a one2many: seznam čísel → `Command.set(ids)`, příkazy `[0, 0, {...}]` zůstávají.
    """
    if not isinstance(values, dict):
        raise ValueError(_lt("values must be an object {field: value}."))
    result = {}
    for name, value in values.items():
        field = model._fields.get(name)
        if field is None:
            raise ValueError(_lt("Field %(field)s does not exist on model %(model)s.", field=name, model=model._name))
        if field.type == "many2one":
            if isinstance(value, dict):
                value = value.get("id")
            elif isinstance(value, (list, tuple)):
                value = value[0] if value else False
        elif field.type in ("one2many", "many2many"):
            value = normalize_commands(model.env[field.comodel_name], field, value)
        result[name] = value
    return result


def normalize_commands(comodel, field, value) -> list:
    if value in (False, None):
        return [Command.clear()]
    if not isinstance(value, (list, tuple)):
        raise ValueError(_lt("Field %s expects a list of IDs or commands.", field.name))
    if all(isinstance(v, int) for v in value):
        return [Command.set(list(value))]
    commands = []
    for command in value:
        if isinstance(command, dict) and "id" in command:
            commands.append(Command.link(command["id"]))
            continue
        if not isinstance(command, (list, tuple)) or not command or not isinstance(command[0], int):
            raise ValueError(_lt("Field %(field)s: command %(command)s is not of the form [code, id, values].",
                                 field=field.name, command=repr(command)))
        code = command[0]
        if code not in (0, 1, 2, 3, 4, 5, 6):
            raise ValueError(_lt("Field %(field)s: unknown command %(code)s.", field=field.name, code=code))
        padded = list(command) + [0] * (3 - len(command))
        if code in (0, 1) and isinstance(padded[2], dict):
            padded[2] = normalize_values(comodel, padded[2])
        commands.append(tuple(padded[:3]))
    return commands


def json_size(data) -> int:
    return len(json.dumps(data, ensure_ascii=False, default=str))
