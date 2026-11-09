# -*- coding: utf-8 -*-
"""Pravidla přístupu přes MCP. Platí průnik tří vrstev:

1. **Odoo:** nástroje běží v prostředí přihlášeného uživatele, takže práva a domény
   z `ir.access` uplatní ORM. Kód pro data nikdy nevolá `sudo()`.
2. **Bez administrátorských skupin a s pevnými zákazy:** modely a pole se posuzují, jako by
   uživatel neměl skupiny Nastavení, Přístupová práva a Technické funkce. Technické modely
   a citlivá pole (hesla, tokeny, klíče) nejsou dostupné nikdy, ani pro čtení.
3. **Pravidla zápisu `mcp.rule`:** bez pravidla se nezapisuje nikam.

**YOLO** (uživatel s `res.users.mcp_yolo`, zapíná ho jen správce): vrstvy 2 a 3 odpadají, platí jen
práva Odoo uživatele, i administrátorská, a technické modely. Zůstává: rozsah tokenu (spojení jen pro
čtení nezapisuje), skrytí hesel, tokenů a klíčů, nedostupné modely MCP, API klíčů a dvoufázového ověření
(`YOLO_DENIED_MODEL_PREFIXES`) a pole `mcp_*`, která jdou měnit jen v Odoo.
"""
import re
from dataclasses import dataclass, field as dc_field
from difflib import SequenceMatcher

from odoo.tools import SQL
from odoo.tools.translate import LazyTranslate

from .i18n import in_english
from .oauth import SCOPE_WRITE

_lt = LazyTranslate(__name__)

ADMIN_GROUPS = ("base.group_system", "base.group_erp_manager", "base.group_no_one")

# Technické a administrátorské modely, ani pro čtení.
DENIED_MODEL_PREFIXES = (
    "ir.", "base.", "base_import.", "bus.", "iap.", "mcp.", "res.config", "res.groups", "res.users.",
    "web_editor.", "web_tour.", "html_editor.", "auth.", "auth_", "change.password", "digest.",
    "certificate.", "spreadsheet.", "privacy.", "discuss.", "mail.",
)
DENIED_MODELS = frozenset({
    "payment.provider", "payment.token", "fetchmail.server", "res.device", "res.device.log",
    "sms.sms", "sms.tracker", "snailmail.letter", "website.visitor",
})
# Číst jde, zapisovat ne: uživatelé (vlastní předvolby, přihlašovací údaje) a firmy jsou správa systému.
DENIED_WRITE_MODELS = frozenset({"res.users", "res.company"})
# Výjimky z prefixů: metadata příloh (obsah se nevrací) a aktivity.
ALLOWED_MODELS = frozenset({"ir.attachment", "mail.activity", "mail.activity.type", "mail.message.subtype"})
# Ani v YOLO: nastavení a audit MCP, API klíče, dvoufázové ověření, uložené platební údaje, certifikáty
# (privátní klíče) a systémové parametry (klíče služeb, tajemství databáze; nastavení jde přes
# res.config.settings).
YOLO_DENIED_MODEL_PREFIXES = (
    "mcp.", "res.users.apikeys", "auth_totp", "auth_passkey", "payment.token", "certificate.",
    "ir.config_parameter",
)
# Pole nastavení MCP (`mcp_yolo`, `mcp_hidden`, pokyny pro AI…) jdou měnit jen v Odoo, ne přes MCP.
MCP_SETTING_FIELD_PREFIX = "mcp_"

SENSITIVE_FIELD = re.compile(
    r"(^|_)(password|passwd|pwd|pass|secret|token|tokens|api_?key|apikey|private_key|access_key|totp|otp_secret|"
    r"signup|pin|pkcs12|p12|pfx|credential|credentials)($|_)"
)
MAGIC_FIELDS = frozenset({"id", "display_name", "create_uid", "create_date", "write_uid", "write_date", "__last_update"})
SKIPPED_TYPES = frozenset({"properties", "properties_definition"})

OPERATION_FLAGS = {
    "create": "perm_create",
    "write": "perm_write",
    "archive": "perm_archive",
    "unlink": "perm_unlink",
    "note": "perm_note",
}
OPERATION_ACCESS = {"create": "create", "write": "write", "archive": "write", "unlink": "unlink", "note": "read"}
OPERATION_LETTERS = {"read": "r", "write": "u", "create": "c", "unlink": "d"}  # ir.access.operation
OPERATION_LABELS = {
    "read": _lt("reading"), "create": _lt("creating"), "write": _lt("editing"), "archive": _lt("archiving"),
    "unlink": _lt("deleting"), "note": _lt("chatter notes"), "action": _lt("running actions"),
}
# Kde se pole používá (do hlášky check_path).
USAGE_FILTER = _lt("in a filter")
USAGE_ORDER = _lt("for sorting")
USAGE_GROUPBY = _lt("for grouping")
USAGE_AGGREGATE = _lt("for aggregates")
# Metody, které nejde povolit ani v pravidle: obešly by kontrolu polí nebo práv.
FORBIDDEN_METHODS = frozenset({
    "create", "write", "unlink", "copy", "copy_data", "read", "search", "search_read", "browse", "sudo",
    "with_user", "with_context", "with_env", "with_company", "load", "import_data", "export_data",
    "toggle_active", "action_archive", "action_unarchive", "message_post", "fields_get", "name_create",
    "web_save", "web_read", "invalidate_recordset", "flush_recordset", "exists", "ensure_one",
})
AGGREGATORS = frozenset({"sum", "avg", "min", "max", "count", "count_distinct"})
GROUP_GRANULARITIES = frozenset({"day", "week", "month", "quarter", "year", "hour",
                                 "year_number", "quarter_number", "month_number", "iso_week_number",
                                 "day_of_year", "day_of_month", "day_of_week", "hour_number"})


PROPOSE_HINT = _lt(
    "Propose a rule with the propose_rule tool (as narrow as possible: only the models, operations and fields "
    "you need) and tell the user to approve it in Odoo (Settings → MCP → Write Rules). It takes effect only "
    "after approval."
)
ASK_ADMIN_HINT = _lt(
    "Tell the user that writing has to be allowed by an Odoo administrator with a rule (Settings → MCP → "
    "Write Rules); this user cannot propose rules."
)


class PolicyError(Exception):
    """Operaci pravidla MCP nedovolují. Text je pro AI klienta i pro člověka.

    Texty v `args` jsou `_lt(...)`, do jazyka uživatele je převede `i18n.error_text`; víc textů se spojí
    mezerou. `str()` vrací angličtinu (logy, testy).
    """

    def __str__(self):
        return " ".join(dict.fromkeys(in_english(arg) for arg in self.args))


class UnknownFieldError(PolicyError):
    """Pole na modelu vůbec není (překlep, název ze starší verze Odoo). V auditu chyba, ne odmítnutí."""


@dataclass
class McpContext:
    """Jedno volání MCP: prostředí uživatele, rozsah tokenu a mezivýsledky kontrol."""
    env: object
    base_url: str
    scopes: frozenset
    auth: str = "oauth"
    client_name: str = ""
    grant_id: int | None = None
    apikey_name: str | None = None
    yolo: bool = False
    cache: dict = dc_field(default_factory=dict)


def cached(ctx: McpContext, key, compute):
    if key not in ctx.cache:
        ctx.cache[key] = compute()
    return ctx.cache[key]


def can_write(ctx: McpContext) -> bool:
    return SCOPE_WRITE in ctx.scopes


def tool_allowed(ctx: McpContext, name: str) -> bool:
    """Nástroj není v Odoo vypnutý ani omezený na jiné lidi (Nastavení → MCP → Nástroje)."""
    denied = cached(ctx, "denied_tools", lambda: ctx.env["mcp.tool"].sudo()._denied_names(ctx.env.user))
    return name not in denied


def write_hint(ctx: McpContext) -> str:
    """Co má AI udělat, když jí zápis chybí: navrhnout pravidlo, nebo poslat uživatele za správcem."""
    return PROPOSE_HINT if tool_allowed(ctx, "propose_rule") else ASK_ADMIN_HINT


# --- skupiny a modely --------------------------------------------------------------------------

def admin_group_ids(env) -> frozenset[int]:
    return frozenset(g.id for g in (env.ref(x, raise_if_not_found=False) for x in ADMIN_GROUPS) if g)


def effective_group_ids(ctx: McpContext) -> frozenset[int]:
    """Skupiny uživatele bez administrátorských (a bez skupin, které jen z nich plynou); v YOLO všechny."""
    def compute():
        if ctx.yolo:
            explicit = ctx.env.user.sudo().group_ids
            return frozenset((explicit | explicit.all_implied_ids).ids)
        admin = admin_group_ids(ctx.env)
        explicit = ctx.env.user.sudo().group_ids.filtered(lambda g: g.id not in admin)
        return frozenset((explicit | explicit.all_implied_ids).ids) - admin
    return cached(ctx, "groups", compute)


def model_denied(model_name: str) -> bool:
    if model_name in ALLOWED_MODELS:
        return False
    return model_name in DENIED_MODELS or model_name.startswith(DENIED_MODEL_PREFIXES)


def yolo_model_denied(model_name: str) -> bool:
    return model_name.startswith(YOLO_DENIED_MODEL_PREFIXES)


def acl_models(ctx: McpContext, operation: str) -> frozenset[str]:
    """Modely, kterým oprávnění `ir.access` skupin bez administrátorských dávají `operation`."""
    def compute():
        ctx.env.cr.execute(SQL(
            """SELECT DISTINCT m.model FROM ir_access a JOIN ir_model m ON m.id = a.model_id
               WHERE a.active AND a.group_id = ANY(%s) AND a.operation LIKE %s""",
            sorted(effective_group_ids(ctx)), f"%{OPERATION_LETTERS[operation]}%",
        ))
        return frozenset(row[0] for row in ctx.env.cr.fetchall())
    return cached(ctx, ("acl", operation), compute)


def model_allowed(ctx: McpContext, model_name: str, operation: str = "read") -> bool:
    """Má uživatel bez administrátorských skupin právo `operation` (read/write/create/unlink)?

    Oprávnění skupin bez administrátorských určí, které modely připadají v úvahu; skutečnou
    kontrolu (i domény oprávnění) pak udělá Odoo jako přihlášený uživatel.
    """
    def compute():
        env = ctx.env
        if ctx.yolo:
            # jen práva Odoo uživatele (i globální a administrátorská), i průvodci (transient)
            if model_name not in env.registry or yolo_model_denied(model_name) or env[model_name]._abstract:
                return False
            return env[model_name].has_access(operation)
        if model_name not in env.registry or model_denied(model_name):
            return False
        if operation != "read" and model_name in DENIED_WRITE_MODELS:
            return False
        model = env[model_name]
        if model._abstract or model._transient or not acl_allowed(ctx, model_name, operation):
            return False
        return model.has_access(operation)
    return cached(ctx, ("model", model_name, operation), compute)


def acl_allowed(ctx: McpContext, model_name: str, operation: str) -> bool:
    """Oprávnění bez administrátorských skupin, i pro rodiče z `_inherits`.

    U rodičů rozhoduje jen oprávnění, ne seznam zakázaných modelů: projekt nebo tým helpdesku dědí
    z `mail.alias` a jinak by byl celý nedostupný. Pole aliasu zůstanou skrytá, vedou na zakázaný model.
    """
    if model_name not in acl_models(ctx, operation):
        return False
    return all(acl_allowed(ctx, parent, operation) and ctx.env[parent].has_access(operation)
               for parent in ctx.env[model_name]._inherits)


def require_model(ctx: McpContext, model_name: str, operation: str = "read"):
    if not isinstance(model_name, str) or model_name not in ctx.env.registry:
        raise PolicyError(_lt("Model %s does not exist. The list_models tool returns the available models.",
                              repr(model_name)))
    if not model_allowed(ctx, model_name, operation):
        raise PolicyError(_lt(
            "Model %(model)s is not available via MCP for %(operation)s (technical or administrative model, "
            "or the user has no access to it).",
            model=model_name, operation=OPERATION_LABELS.get(operation, operation),
        ))
    return ctx.env[model_name]


def readable_models(ctx: McpContext) -> list[str]:
    return sorted(name for name in ctx.env.registry if model_allowed(ctx, name, "read"))


# --- pole --------------------------------------------------------------------------------------

def groups_allowed(ctx: McpContext, spec: str | None) -> bool:
    """Atribut `groups` pole (`"a.b,!c.d"`) vyhodnocený proti skupinám bez administrátorských."""
    if not spec:
        return True
    if spec == ".":
        return False
    groups = effective_group_ids(ctx)

    def member(xmlid: str) -> bool:
        group = ctx.env.ref(xmlid, raise_if_not_found=False)
        return bool(group) and group.id in groups

    items = [item.strip() for item in spec.split(",") if item.strip()]
    negatives = [item[1:] for item in items if item.startswith("!")]
    positives = [item for item in items if not item.startswith("!")]
    if any(member(x) for x in negatives):
        return False
    return any(member(x) for x in positives) or not positives


def hidden_fields(ctx: McpContext) -> frozenset:
    """Pole označená v Odoo jako skrytá pro MCP (`ir.model.fields.mcp_hidden`)."""
    def compute():
        ctx.env.cr.execute(SQL("SELECT model, name FROM ir_model_fields WHERE mcp_hidden"))
        return frozenset(ctx.env.cr.fetchall())
    return cached(ctx, "hidden", compute)


def field_readable(ctx: McpContext, model_name: str, fname: str) -> bool:
    key = ("field", model_name, fname)
    if key not in ctx.cache:
        ctx.cache[key] = False  # ochrana proti cyklům u related polí
        ctx.cache[key] = _field_readable(ctx, model_name, fname)
    return ctx.cache[key]


def _field_readable(ctx: McpContext, model_name: str, fname: str) -> bool:
    field = ctx.env[model_name]._fields.get(fname)
    if field is None:
        return False
    if fname in ("id", "display_name"):
        return True
    if field.type in SKIPPED_TYPES or SENSITIVE_FIELD.search(fname):
        return False
    if not ctx.yolo and (model_name, fname) in hidden_fields(ctx):
        return False
    if field.groups and not groups_allowed(ctx, field.groups):
        return False
    if field.relational and not model_allowed(ctx, field.comodel_name, "read"):
        return False
    if field.related and related_target(ctx, model_name, field.related) is None:
        return False
    return True


def related_target(ctx: McpContext, model_name: str, path) -> tuple[str, str] | None:
    """Projde cestu `partner_id.country_id.code`; každé pole po cestě musí jít číst."""
    names = path.split(".") if isinstance(path, str) else list(path)
    current = model_name
    for index, name in enumerate(names):
        if not field_readable(ctx, current, name):
            return None
        if index < len(names) - 1:
            field = ctx.env[current]._fields[name]
            if not field.relational:
                return None
            current = field.comodel_name
    return current, names[-1]


def readable_fields(ctx: McpContext, model_name: str) -> list[str]:
    return [name for name in ctx.env[model_name]._fields if field_readable(ctx, model_name, name)]


def default_fields(ctx: McpContext, model_name: str, limit: int = 30) -> list[str]:
    """Rozumná výchozí pole pro výpis: jednoduché uložené hodnoty, bez textů a vazeb na více záznamů."""
    fields_map = ctx.env[model_name]._fields
    simple = ("char", "integer", "float", "monetary", "boolean", "date", "datetime", "selection", "many2one")
    names = [
        name for name in readable_fields(ctx, model_name)
        if name not in MAGIC_FIELDS and fields_map[name].store and fields_map[name].type in simple
    ]
    return ["display_name"] + names[:limit]


def similar_fields(ctx: McpContext, model_name: str, fname: str, limit: int = 3) -> list[str]:
    """Pole, která AI nejspíš myslela: podobný název nebo stejné poslední slovo (`product_uom_id` → `uom_id`).

    Nabízí jen pole čitelná přes MCP, aby hláška neprozradila skrytá.
    """
    def words(name):
        return [part for part in name.split("_") if part and part not in ("id", "ids")]
    wanted = words(fname)
    scored = []
    for name in readable_fields(ctx, model_name):
        have = words(name)
        score = SequenceMatcher(None, fname, name).ratio()
        if set(wanted) & set(have):
            score += 0.2
        if wanted and have and wanted[-1] == have[-1]:
            score += 0.4
        if fname.endswith("_" + name) or name.endswith("_" + fname) or (have and set(have) <= set(wanted)):
            score += 0.3
        if score >= 0.6:
            scored.append((-score, name))
    return [name for _score, name in sorted(scored)[:limit]]


def unknown_fields(ctx: McpContext, model_name: str, names) -> UnknownFieldError:
    model = ctx.env[model_name]
    texts = []
    for name in names:
        similar = similar_fields(ctx, model_name, name)
        if similar:
            labels = ", ".join(f"{s} ({model._fields[s].get_description(ctx.env, ['string'])['string']})"
                               for s in similar)
            texts.append(_lt("Field %(field)s does not exist on model %(model)s. Similar fields: %(similar)s.",
                             field=name, model=model_name, similar=labels))
        else:
            texts.append(_lt("Field %(field)s does not exist on model %(model)s.", field=name, model=model_name))
    return UnknownFieldError(*texts, _lt("describe_model lists all available fields."))


def require_known_fields(ctx: McpContext, model_name: str, names) -> None:
    unknown = [name for name in names if name not in ctx.env[model_name]._fields]
    if unknown:
        raise unknown_fields(ctx, model_name, unknown)


def check_fields(ctx: McpContext, model_name: str, field_names) -> list[str]:
    if not isinstance(field_names, list) or not all(isinstance(f, str) for f in field_names):
        raise PolicyError(_lt("fields must be a list of field names."))
    require_known_fields(ctx, model_name, field_names)
    hidden = [f for f in field_names if not field_readable(ctx, model_name, f)]
    if hidden:
        raise PolicyError(_lt(
            "Fields %(fields)s on model %(model)s exist but cannot be read via MCP (they are hidden or outside "
            "this user's access).",
            fields=", ".join(hidden), model=model_name,
        ))
    return list(dict.fromkeys(field_names))


def check_path(ctx: McpContext, model_name: str, path: str, usage) -> tuple[str, str]:
    """`usage` je jedna z konstant USAGE_… (do hlášky, kde pole nejde použít)."""
    if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", path):
        raise PolicyError(_lt("%s is not a field name.", repr(path)))
    names = path.split(".")
    current = model_name
    for index, name in enumerate(names):
        require_known_fields(ctx, current, [name])
        if not field_readable(ctx, current, name):
            raise PolicyError(_lt(
                "Field %(field)s on model %(model)s exists but cannot be used %(usage)s via MCP (it is hidden or "
                "outside this user's access).",
                field=name, model=current, usage=usage,
            ))
        if index < len(names) - 1:
            field = ctx.env[current]._fields[name]
            if not field.relational:
                raise PolicyError(_lt(
                    "%(path)s is not a valid path: field %(field)s on model %(model)s is not a relation.",
                    path=path, field=name, model=current,
                ))
            current = field.comodel_name
    return current, names[-1]


def check_domain(ctx: McpContext, model_name: str, domain, depth: int = 0) -> list:
    """Každé pole v doméně musí jít číst, jinak by šlo skrytou hodnotu vyzkoušet filtrem."""
    if domain in (None, False):
        return []
    if not isinstance(domain, list):
        raise PolicyError(_lt('domain must be a list, e.g. [["name", "ilike", "cheese"]].'))
    if depth > 5:
        raise PolicyError(_lt("The domain is nested too deeply."))
    for item in domain:
        if isinstance(item, str):
            if item not in ("&", "|", "!"):
                raise PolicyError(_lt("Unknown operator %s in the domain.", repr(item)))
            continue
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            raise PolicyError(_lt("Condition %s is not of the form [field, operator, value].", repr(item)))
        path, operator, value = item
        if isinstance(path, int) and path in (0, 1):
            continue
        target_model, target_field = check_path(ctx, model_name, path, USAGE_FILTER)
        if isinstance(operator, str) and operator.startswith(("any", "not any")) and isinstance(value, list):
            comodel = ctx.env[target_model]._fields[target_field].comodel_name
            check_domain(ctx, comodel, value, depth + 1)
    return domain


def check_order(ctx: McpContext, model_name: str, order: str | None) -> str | None:
    if not order:
        return None
    if not isinstance(order, str):
        raise PolicyError(_lt('order must be a string, e.g. "date desc, id".'))
    for part in order.split(","):
        tokens = part.split()
        if not tokens:
            continue
        if any(t.lower() not in ("asc", "desc", "nulls", "first", "last") for t in tokens[1:]):
            raise PolicyError(_lt('Sort order %s is not of the form "field asc|desc".', repr(part.strip())))
        check_path(ctx, model_name, tokens[0], USAGE_ORDER)
    return order


def check_groupby(ctx: McpContext, model_name: str, groupby) -> list[str]:
    if isinstance(groupby, str):
        groupby = [groupby]
    if not isinstance(groupby, list) or not all(isinstance(g, str) for g in groupby):
        raise PolicyError(_lt('groupby must be a list, e.g. ["date_order:month", "partner_id"].'))
    for spec in groupby:
        name, _sep, granularity = spec.partition(":")
        if granularity and granularity not in GROUP_GRANULARITIES:
            raise PolicyError(_lt("Unknown grouping %s.", repr(granularity)))
        check_path(ctx, model_name, name, USAGE_GROUPBY)
    return groupby


def check_aggregates(ctx: McpContext, model_name: str, aggregates) -> list[str]:
    if not aggregates:
        return ["__count"]
    if not isinstance(aggregates, list) or not all(isinstance(a, str) for a in aggregates):
        raise PolicyError(_lt('aggregates must be a list, e.g. ["amount_total:sum", "__count"].'))
    for spec in aggregates:
        if spec == "__count":
            continue
        name, _sep, aggregator = spec.partition(":")
        if aggregator not in AGGREGATORS:
            raise PolicyError(_lt("Aggregate %(spec)s must be of the form field:%(aggregators)s.",
                                  spec=repr(spec), aggregators="|".join(sorted(AGGREGATORS))))
        check_path(ctx, model_name, name, USAGE_AGGREGATE)
    return aggregates


# --- pravidla zápisu ---------------------------------------------------------------------------

def user_rules(ctx: McpContext):
    """Schválená aktivní pravidla, která platí pro přihlášeného uživatele (bez uživatelů = pro všechny).

    Návrhy od AI (stav proposed) neplatí, dokud je člověk v Odoo neschválí.
    """
    def compute():
        uid = ctx.env.uid
        rules = ctx.env["mcp.rule"].sudo().search([("active", "=", True), ("state", "=", "approved")])
        return rules.filtered(lambda r: not r.user_ids or uid in r.user_ids.ids)
    return cached(ctx, "rules", compute)


def rule_models(ctx: McpContext, rule) -> frozenset[str]:
    return cached(ctx, ("rule_models", rule.id), lambda: frozenset(rule._get_model_names()))


def available_operations(ctx: McpContext) -> set[str]:
    """Které druhy zápisu má uživatel v pravidlech (podle toho se nabízejí nástroje); v YOLO všechny."""
    if not can_write(ctx):
        return set()
    if ctx.yolo:
        return {*OPERATION_FLAGS, "action"}
    operations = {op for rule in user_rules(ctx) for op, flag in OPERATION_FLAGS.items() if rule[flag]}
    if any(rule._get_action_names() for rule in user_rules(ctx)):
        operations.add("action")
    return operations


def require_write_scope(ctx: McpContext) -> None:
    if not can_write(ctx):
        hint = _lt("You can still propose a write rule with the propose_rule tool.")
        raise PolicyError(
            _lt('This connection is read-only. To write, the user has to connect again and tick "Also allow '
                'writing" on the consent page (for an API key, choose the scope "MCP – read and write").'),
            *([hint] if tool_allowed(ctx, "propose_rule") else []),
        )


def access_denied(model_name: str, operation: str) -> PolicyError:
    return PolicyError(_lt(
        "Without administrator rights, the user's access to model %(model)s does not include %(operation)s.",
        model=model_name, operation=OPERATION_LABELS[operation],
    ))


def too_many_records(rule) -> PolicyError:
    return PolicyError(_lt('Rule "%(rule)s" allows at most %(count)s records at once.',
                           rule=rule.name, count=rule.max_records))


def check_write(ctx: McpContext, model_name: str, operation: str, records=None, values=None, depth: int = 0):
    """Ověří zápis podle pravidel; vrátí pravidlo, které ho povolilo (v YOLO None). Jinak PolicyError."""
    require_write_scope(ctx)
    if depth > 3:
        raise PolicyError(_lt("Relation commands are nested too deeply."))
    require_model(ctx, model_name, "read")
    if not model_allowed(ctx, model_name, OPERATION_ACCESS[operation]):
        raise access_denied(model_name, operation)
    if ctx.yolo:
        # bez pravidel: jen práva Odoo, kontrola polí (skrytá, nastavení MCP) a příkazů x2many
        for name, value in (values or {}).items():
            check_field_write(ctx, None, model_name, name, value, None, depth)
        return None
    rules = [r for r in user_rules(ctx) if r[OPERATION_FLAGS[operation]] and model_name in rule_models(ctx, r)]
    if not rules:
        raise PolicyError(_lt("MCP rules do not allow %(operation)s on model %(model)s.",
                              operation=OPERATION_LABELS[operation], model=model_name), write_hint(ctx))
    errors = []
    for rule in rules:
        try:
            _check_rule(ctx, rule, model_name, operation, records, values, depth)
            return rule
        except UnknownFieldError:
            raise  # neexistující pole nezávisí na pravidle
        except PolicyError as error:
            errors.extend(error.args)
    raise PolicyError(*errors)


def _check_rule(ctx, rule, model_name, operation, records, values, depth):
    if records is not None and rule.max_records and len(records) > rule.max_records:
        raise too_many_records(rule)
    check_rule_domain(rule, records)
    if values:
        allowed = rule._get_field_names(model_name)
        for name, value in values.items():
            check_field_write(ctx, rule, model_name, name, value, allowed, depth)


def check_rule_domain(rule, records) -> None:
    if rule is None:  # YOLO: zápis nepovolilo pravidlo
        return
    domain = rule._get_domain()
    if not domain or not records:
        return
    outside = records - records.filtered_domain(domain)
    if outside:
        raise PolicyError(_lt('Records %(ids)s do not match the condition of rule "%(rule)s".',
                              ids=", ".join(map(str, outside.ids)), rule=rule.name))


def check_field_write(ctx, rule, model_name, name, value, allowed, depth):
    field = ctx.env[model_name]._fields.get(name)
    if field is None:
        raise unknown_fields(ctx, model_name, [name])
    if name in MAGIC_FIELDS:
        raise PolicyError(_lt("Field %s cannot be written.", name))
    if name.startswith(MCP_SETTING_FIELD_PREFIX):
        raise PolicyError(_lt("Field %s is a setting of the MCP server, it can only be changed in Odoo.", name))
    if not field_readable(ctx, model_name, name):
        raise PolicyError(_lt("Field %s is hidden via MCP.", name))
    if field.related:
        # related a zděděná pole (`_inherits`) se zapisují do cílového modelu, rozhodují jeho pravidla
        target_model, target_field = related_target(ctx, model_name, field.related)
        if target_model != model_name:
            check_write(ctx, target_model, "write", values={target_field: value}, depth=depth + 1)
            return
    if allowed is not None and name not in allowed:
        raise PolicyError(_lt(
            'Rule "%(rule)s" does not allow field %(field)s on model %(model)s. Allowed fields: %(allowed)s.',
            rule=rule.name, field=name, model=model_name, allowed=", ".join(sorted(allowed)) or _lt("none"),
        ))
    if field.compute and not field.inverse and not field.store and not field.related:
        raise PolicyError(_lt("Field %s is computed and cannot be written.", name))
    if allowed is None and field.readonly and not ctx.yolo:
        raise PolicyError(_lt(
            "Field %s is read-only in Odoo. It can only be written when a rule lists it explicitly.", name,
        ))
    if field.type in ("one2many", "many2many"):
        check_commands(ctx, field, value, depth)


def check_commands(ctx, field, commands, depth):
    """Příkazy pro x2many zakládají, mění nebo mažou záznamy jiného modelu: i ty musí pravidla povolit."""
    comodel = ctx.env[field.comodel_name]
    for command in commands:
        code = command[0]
        if code == 0:
            check_write(ctx, comodel._name, "create", values=command[2] or {}, depth=depth + 1)
        elif code == 1:
            check_write(ctx, comodel._name, "write", records=comodel.browse(command[1]),
                        values=command[2] or {}, depth=depth + 1)
        elif code == 2 or (field.type == "one2many" and code in (3, 5, 6)):
            # u one2many odpojení řádku obvykle znamená jeho smazání
            ids = [command[1]] if code in (2, 3) else []
            check_write(ctx, comodel._name, "unlink", records=comodel.browse(ids) if ids else None, depth=depth + 1)


def check_action(ctx: McpContext, model_name: str, method: str, records):
    require_write_scope(ctx)
    if not isinstance(method, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", method) or method in FORBIDDEN_METHODS:
        raise PolicyError(_lt("Method %s cannot be run via MCP.", repr(method)))
    require_model(ctx, model_name, "read")
    if not model_allowed(ctx, model_name, "write"):
        raise access_denied(model_name, "write")
    if ctx.yolo:
        return None
    rules = [r for r in user_rules(ctx) if method in r._get_action_names() and model_name in rule_models(ctx, r)]
    if not rules:
        raise PolicyError(_lt("Action %(method)s on model %(model)s is not allowed by the MCP rules.",
                              method=method, model=model_name), write_hint(ctx))
    errors = []
    for rule in rules:
        try:
            if rule.max_records and len(records) > rule.max_records:
                raise too_many_records(rule)
            check_rule_domain(rule, records)
            return rule
        except PolicyError as error:
            errors.extend(error.args)
    raise PolicyError(*errors)


def report_allowed(ctx: McpContext, report) -> bool:
    groups = report.sudo().group_ids
    return model_allowed(ctx, report.model, "read") and (
        not groups or bool(set(groups.ids) & effective_group_ids(ctx))
    )
