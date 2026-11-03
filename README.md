# MCP server s OAuth (Odoo 20)

Remote MCP server přímo v Odoo, přes který se k Odoo připojí Claude jako vlastní konektor:
claude.ai na webu, desktopová aplikace, mobil, Cowork i Claude Code. Odoo je zároveň OAuth 2.1
server, takže se přihlásíš běžným účtem Odoo a nic nekopíruješ. Pro Claude Code jde použít i API klíč.

## Co umí

- **Výchozí jen čtení.** Nástroje běží jako přihlášený uživatel, takže platí jeho práva v Odoo.
- **Bez administrátorských práv.** Modely a pole se posuzují, jako by uživatel neměl skupiny
  Nastavení, Přístupová práva a Technické funkce.
  - Technické modely (`ir.*`, `res.groups`, `res.users.*`, `mail.*`, `discuss.*`, `certificate.*` a další)
    nejsou dostupné vůbec, ani pro čtení. Výjimky jsou metadata příloh a aktivity.
  - Uživatele a firmy jde číst, ne upravovat.
- **Citlivá pole jsou skrytá vždy:**
  - hesla, tokeny, klíče, tajemství, PIN, certifikáty;
  - pole jen pro administrátory (atribut `groups`), třeba tokeny bankovních a platebních služeb;
  - další pole jde skrýt v Odoo.
- **Zápis podle pravidel** po aplikacích (Produkty, Sklady, Prodej…), volitelně jen vyjmenovaná pole,
  jen záznamy podle domény a vybrané akce. Uživatel ho musí povolit i při připojení klienta.
- **Reporty v PDF** (faktury a další): odkaz ke stažení platný 15 minut.
- **Audit** všech volání a značka „přes MCP“ v chatteru u změn.
- **Česky i anglicky** podle jazyka přihlášeného uživatele (Odoo i texty pro AI), viz [Jazyky](#jazyky).

## Adresy

| adresa | k čemu |
|---|---|
| `/api/mcp` | MCP (Streamable HTTP, JSON bez SSE, bezstavový) |
| `/.well-known/oauth-protected-resource/api/mcp` | metadata chráněného zdroje (RFC 9728) |
| `/.well-known/oauth-authorization-server` | metadata OAuth serveru (RFC 8414) |
| `/api/mcp/oauth/authorize` | přihlášení a souhlas |
| `/api/mcp/oauth/token` | tokeny (kód + PKCE S256, obnova s rotací) |
| `/api/mcp/oauth/register` | dynamická registrace klientů (RFC 7591) |
| `/api/mcp/oauth/revoke` | odvolání tokenu (RFC 7009) |
| `/api/mcp/download/<token>` | stažení PDF z nástroje `get_report` |

`/mcp` patří vestavěnému MCP serveru Odoo Enterprise, proto `/api/mcp`.

## Připojení

### claude.ai, desktop a mobil

Potřebuje veřejnou adresu přes HTTPS, Claude se připojuje z cloudu Anthropicu (`160.79.104.0/21`).

1. claude.ai → Nastavení → Konektory → Přidat vlastní konektor.
2. Adresa `https://<adresa-odoo>/api/mcp`, nic dalšího nevyplňovat.
3. Připojit → přihlášení do Odoo → stránka souhlasu.
   - Zápis je ve výchozím stavu vypnutý. Pro zápis zaškrtni „Povolit i zápis“.
4. Claude se zaregistruje sám přes popis klienta na claude.ai (CIMD), záložně přes DCR.

### Claude Code přes OAuth

```bash
claude mcp add --transport http odoo http://localhost:8069/api/mcp
```

Pak v Claude Code `/mcp` → odoo → Authenticate a v prohlížeči souhlas.

- Claude Code se přesměruje zpět na `http://localhost:<port>/callback`. Stránka souhlasu na to upozorní.
- Specifikace MCP chce pro OAuth server HTTPS. Pokud Claude Code s `http://localhost` OAuth odmítne,
  použij API klíč.

### Claude Code přes API klíč

1. V Odoo Předvolby → Zabezpečení účtu → Vytvořit API klíč.
2. Scope **MCP – jen čtení**, nebo **MCP – čtení a zápis**.
3. Připojit:

   ```bash
   claude mcp add --transport http odoo http://localhost:8069/api/mcp --header "Authorization: Bearer <klíč>"
   ```

- Klíč se scope MCP se k ničemu jinému nehodí.
- Běžný API klíč (scope RPC) do MCP nepustí.
- Zápis řídí pravidla stejně jako u OAuth.

### ChatGPT

V režimu vývojáře ChatGPT: Connectors → Create, adresa `/api/mcp`, OAuth.

- Server splňuje požadavky ChatGPT: CIMD z `chatgpt.com`, adresy přesměrování
  `https://chatgpt.com/connector_platform_oauth_redirect` a `https://chatgpt.com/connector/oauth/*`,
  parametr `iss` v odpovědi (RFC 9207).
- Neověřeno.

## Pokyny pro AI

Nastavení → MCP → Pokyny pro AI, pro každou firmu zvlášť (firma přihlášeného uživatele):

- **Název systému pro AI:** jak se Odoo představí, třeba „Odoo Moje firma“.
  - Je v titulku serveru a na začátku popisu nástroje `whoami`.
  - Když má klient připojených víc Odoo (třeba dvě firmy), pozná, které je které.
- **Co je tohle Odoo:** pár vět, čí systém to je a co v něm je.
- **Pravidla pro AI:** firemní pravidla pro čtení i zápis.

AI je dostane hned při připojení (pokyny serveru MCP, před technickými pokyny) a znovu v `whoami`. Popis
`whoami` jí říká, ať ho zavolá jako první. Dohromady nejvýš 8 000 znaků.

**Když popis chybí** (Co je tohle Odoo je prázdné), `whoami` vrátí v `system.setup_needed` pokyn pro AI:

- jednou se zeptá uživatele, co firma dělá a jaká pravidla má dodržovat;
- z odpovědi navrhne text k vložení do Pokynů pro AI, s odkazem na formulář (`/odoo/mcp-ai-instructions`);
- uložit ho sama nemůže, firmy jdou přes MCP jen číst;
- uživateli bez práv správce řekne, ať text předá správci.

## Jazyky

Zdrojové texty modulu jsou anglicky (zvyklost Odoo), čeština je v `i18n/cs.po`. Jazyk určí přihlášený
uživatel (Předvolby → Jazyk), takže v jedné databázi může být modul pro někoho anglicky a pro jiného česky.

- **V Odoo:** menu, formuláře, pole, souhrn pravidla a štítek návrhu od AI v chatteru.
- **Pro AI klienta:** názvy a popisy nástrojů i parametrů, pokyny serveru, chybové hlášky a poznámky ve
  výsledcích. Klient si nástroje načte při připojení, změna jazyka se projeví v nové konverzaci.
- **Stránka souhlasu OAuth** je v jazyce přihlášeného uživatele, ne prohlížeče.
- **Pokyny pro AI** (název systému, popis, pravidla) se nepřekládají, AI je dostane tak, jak jsou napsané.
- **Vždy anglicky:**
  - chyby OAuth pro klienta (`error_description`), protože RFC 6749 tam dovoluje jen ASCII; na stránce
    chyby v prohlížeči jsou přeložené;
  - chyby protokolu JSON-RPC a logy.

Překlad nového textu:

1. **Napsat ho anglicky:**
   - `env._("…")` v kódu, který má prostředí;
   - `_lt("…")` u konstant na úrovni modulu a výjimek v `lib`
     (`_lt = LazyTranslate(__name__)`, `PolicyError(_lt("…", …))`).
2. **Vyexportovat šablonu:**
   `odoo i18n export -d <db> -o /tmp/mcp_oauth_server.pot mcp_oauth_server`, uložit ji do `i18n/` a doplnit
   překlad do `cs.po` (stejné `%s` a `%(name)s` jako v originále).
3. **Aktualizovat modul a restartovat Odoo.** Překlady textů v kódu si Odoo drží v paměti procesu.

Past: extraktor překladů vezme jako text i řetězec za `),(` po volání `_lt(…)`, třeba z n-tic
`("perm_write", _lt("edit"))`. Proto jsou takové dvojice ve slovníku a pojmenovaný argument
`required=(…)` u `schema`.

## Vypnutí a omezení nástrojů

Nastavení → MCP → Nástroje: seznam všech nástrojů. Doplní se při instalaci a aktualizaci modulu.

- **Povoleno:** vypnutý nástroj AI klient vůbec nevidí.
- **Jen pro skupiny / Jen pro uživatele:** prázdné = všichni. Jinak stačí být v jedné skupině nebo mezi
  uživateli. Rozhodují skutečné skupiny uživatele, i administrátorské.
- **`propose_rule`** je po instalaci jen pro skupinu Nastavení, tedy pro správce. Ostatním AI poradí, ať
  požádají správce o pravidlo.
- **Zápis** navíc řídí pravidla zápisu: nástroj pro zápis se nabídne, jen když je povolený tady i v pravidlech.

## Návrhy odpovědí (helpdesk, úkoly…)

Nástroj `draft_reply` připraví odpověď do chatteru záznamu: ticket v helpdesku, úkol, objednávka, cokoli
s chatterem. Typické zadání v Claude Code: „Ticket 1234, zjisti problém v kódu a připrav odpověď.“

1. **Načtení ticketu.** AI ticket najde (`search_read`, `name_search`) a přečte konverzaci (`get_chatter`).
2. **Uložení návrhu.** Návrh se uloží jako naplánovaná zpráva Odoo (`mail.scheduled.message`) s příznakem
   „návrh od AI“:
   - autorem je přihlášený uživatel;
   - příjemci jako u běžné odpovědi (u ticketu zákazník), nebo `partner_ids`;
   - text se vyčistí (žádné skripty ani atributy), prostý text se převede na odstavce;
   - starší návrh od AI na stejném záznamu se nahradí.
3. **V chatteru** je návrh nad konverzací se štítkem **Návrh od AI · neodešle se sám** a tlačítky
   **Odeslat nyní**, **Upravit** a **Zrušit**. Odejde jako běžná zpráva od uživatele, s e-mailem zákazníkovi.
4. **Aktivita.** K záznamu se založí aktivita „Zkontrolovat návrh odpovědi od AI“, takže všechny čekající
   návrhy jsou v ikoně aktivit. Po odeslání nebo zrušení návrhu zmizí.

Pojistky:

- **Cron návrhy od AI přeskakuje**, i když jejich datum uplyne. Odeslat je jde jen tlačítkem.
- **Návrh nic neodesílá.** Proto jde i ze spojení jen pro čtení, stejně jako `propose_rule`. V Nástrojích ho
  jde vypnout nebo povolit jen někomu.
- **Pokyny serveru AI říkají**, ať zákazníkům nic neposílá a odpovědi jen připravuje.
- Ověřeno v Community na úkolech v projektech. Helpdesk je Enterprise a používá stejný chatter.

## Vlastní nástroje z jiných addonů

Jiný addon přidá nástroj děděním modelu `mcp.tool` a metodou `_mcp_extra_tools()`. Protože jde o dědění
v Odoo, nástroj existuje jen v databázích, kde je ten addon nainstalovaný. Po instalaci a aktualizaci addonu se
objeví v Nastavení → MCP → Nástroje (sloupec Z modulu). Jde ho tam vypnout nebo omezit jako vestavěné nástroje.

```python
# __manifest__.py: "depends": ["mcp_oauth_server", "helpdesk"]
from odoo import api, models
from odoo.tools.translate import LazyTranslate

from odoo.addons.mcp_oauth_server.lib.policy import check_fields, require_model
from odoo.addons.mcp_oauth_server.lib.serialize import format_records
from odoo.addons.mcp_oauth_server.lib.tools import READ_ANNOTATIONS, Tool, browse_existing, ids_argument, schema

_lt = LazyTranslate(__name__)  # překlady z i18n/*.po tohohle addonu


def tool_ticket_overview(ctx, args):
    """Přehled ticketu: běží jako přihlášený uživatel, pole jen podle pravidel MCP."""
    Ticket = require_model(ctx, "helpdesk.ticket")
    ticket = browse_existing(Ticket, ids_argument(args, "id", 1))
    names = check_fields(ctx, Ticket._name, ["name", "partner_id", "stage_id", "team_id", "priority"])
    return {"ticket": format_records(ticket, names, ctx.base_url)[0]}


class McpTool(models.Model):
    _inherit = "mcp.tool"

    @api.model
    def _mcp_extra_tools(self):
        return super()._mcp_extra_tools() + [
            Tool("helpdesk_ticket_overview", _lt("Ticket overview"),
                 _lt("Customer, stage, team and priority of a ticket by ID."),
                 schema({"id": {"type": "integer"}}, required=("id",)), tool_ticket_overview, READ_ANNOTATIONS,
                 instructions=_lt("For tickets, start with helpdesk_ticket_overview.")),
        ]
```

### Co nástroj dostane a co musí dodržet

- **`ctx`** (`McpContext`):
  - `ctx.env` je prostředí přihlášeného uživatele s jeho jazykem a firmami;
  - dál `ctx.base_url`, `ctx.client_name` a `ctx.scopes`.
- **Kontroly MCP musí nástroj zavolat sám.** ORM hlídá jen práva Odoo. Skrytá pole, odebrání
  administrátorských práv a pravidla zápisu musí nástroj uplatnit přes funkce z `lib/policy.py`:
  - `require_model(ctx, model, operation)`: model je přes MCP dostupný;
  - `check_fields`, `readable_fields`, `default_fields` a `check_domain`: pole a domény jen podle pravidel.
    K vrácení hodnot `serialize.format_records`;
  - `check_write(ctx, model, operation, records, values)`, nebo jen `require_write_scope(ctx)`: zápis podle
    pravidel a rozsahu spojení;
  - `PolicyError(_lt("…"))`: srozumitelná chyba pro AI v jazyce uživatele, do auditu jako „odmítnuto“.
    Texty ve výsledku nástroje přes `ctx.env._("…")`.
- **Pomocné funkce** v `lib/tools.py`: `browse_existing`, `ids_argument`, `clamp`, `run_write` (náhled
  s návratem zpět), `schema`, `READ_ANNOTATIONS`.
- **`Tool`:**
  - `readonly=True` běží v savepointu, který se vždy vrátí zpět. Nástroj, který zapisuje, musí mít
    `readonly=False`;
  - `operation` naváže nástroj na pravidla zápisu (create, write, archive, unlink, note, action);
  - `kind` je štítek v Nástrojích;
  - `default_groups` omezí nástroj při prvním založení, třeba `("base.group_system",)`;
  - `instructions` přidá řádek do pokynů serveru, když uživatel nástroj má;
  - `title`, `description`, popisy v `schema` a `instructions` jako `_lt("…")` se přeloží do jazyka
    uživatele z `i18n/*.po` addonu nástroje, obyčejný text zůstane, jak je.
- **Pojmenování a chyby:**
  - název nástroje: malá písmena, číslice a podtržítka, s prefixem addonu, třeba `helpdesk_…`;
  - vestavěný nástroj nejde přepsat;
  - vadný nástroj se vynechá a zapíše jednou do logu, MCP kvůli němu nespadne.
- **Addon, který má fungovat i bez MCP**, dá nástroje do malého propojovacího modulu s `"auto_install": True`
  a `"depends": ["mcp_oauth_server", "<addon>"]`.

## Pravidla zápisu

V Odoo: Nastavení → MCP → Pravidla zápisu. Bez pravidla AI klient jen čte.

- **Aplikace:** řádek Přístupová práva z formuláře uživatele (`res.groups.privilege`).
  - Pravidlo pokryje modely, pro které tahle aplikace v Odoo sama definuje oprávnění k zakládání nebo
    úpravám (stejný modul jako model). Produkty mají 17 modelů: šablony, varianty, kategorie,
    ceníky, atributy, dodavatele…
  - Sdílené modely (kontakty, produkty) patří jen své aplikaci. Zápis do Skladů tak neotevře zápis do
    kontaktů.
  - Další modely jde přidat a vyjmout ručně. Seznam je na záložce Modely.
- **Operace:**
  - zakládat, upravovat, archivovat, mazat, poznámky do chatteru;
  - akce: jen vyjmenované metody, třeba `action_confirm`.
- **Jen tato pole:** prázdné = všechna pole kromě skrytých, citlivých a polí jen pro čtení. Pole jen pro
  čtení (třeba `state`) jde zapisovat, jen když je pravidlo vyjmenuje.
- **Jen záznamy:** doména, kterou záznam musí splňovat před zápisem i po něm.
- **Nejvýš záznamů najednou** (výchozí 50) a **Uživatelé** (prázdné = všichni interní).

### Návrhy pravidel od AI

Pravidla nemusíš psát ručně. Když AI klientovi zápis chybí, navrhne pravidlo sám nástrojem `propose_rule`:

1. **Kdy AI navrhne.** Pozná to z `whoami`, z chybějících nástrojů pro zápis nebo z odmítnutí. Každá odpověď
   „nemáš právo“ mu radí navrhnout co nejužší pravidlo.
2. **Co se uloží.** Pravidlo ve stavu **Návrh od AI**. Neplatí, dokud ho člověk neschválí.
   - platí jen pro uživatele, který ho přes AI navrhl;
   - AI musí uvést zdůvodnění, uvidíš ho při schvalování;
   - uživateli přibude aktivita „Schválit pravidlo MCP“;
   - AI dostane odkaz do Odoo, který ti pošle.
3. **Kontrola a schválení.** Nastavení → MCP → Návrhy od AI. Návrh můžeš před schválením zúžit (modely,
   operace, pole, domény). Pak tlačítko **Schválit**, nebo **Zamítnout**. Schválené pravidlo jde tlačítkem
   Pozastavit vrátit mezi návrhy.
4. **Načtení nástrojů.** Po schválení je potřeba spojení s povoleným zápisem a nová konverzace, aby klient
   načetl nástroje pro zápis.

Pojistky:

- Přes MCP pravidlo vznikne vždy jen jako návrh, i kdyby AI poslala stav „schváleno“.
- Přes MCP nejde žádné pravidlo schválit ani změnit, i když MCP běží pod administrátorem.
- Schvalovat smí jen správce (skupina Nastavení).
- Změny pravidel a schválení jsou v chatteru pravidla.
- Návrh na technický nebo zakázaný model, neznámou aplikaci, skryté pole nebo zakázanou metodu se rovnou
  odmítne.
- Jeden uživatel může mít nejvýš 20 neschválených návrhů.

Pravidla založená ručně v Odoo jsou schválená hned.

Kontroly, které platí vždy:

- **Vazby:**
  - příkazy x2many (`[0, 0, {...}]` a další) kontrolují pravidla cílového modelu;
  - related a zděděná pole (`_inherits`) se posuzují podle modelu, kam se skutečně zapisují.
- **Model:** uživatel na něj musí mít právo i bez administrátorských skupin.
- **Náhled:** každý zápis umí `preview`, změna se provede a vrátí zpět.
  - Pozor, sekvence v Postgresu se nevracejí. Náhled dokladu s běžnou číselnou řadou spotřebuje číslo.

## Skrytá pole

Nastavení → MCP → Skrytá pole. Zruš filtr, najdi pole a zapni „Skryté pro MCP“.

Skryté pole AI klient neuvidí a nejde ho použít ani ve filtru, řazení nebo seskupení. Jinak by šla hodnota
zjistit zkoušením.

## Nástroje

| nástroj | co dělá |
|---|---|
| `whoami` | uživatel, firma, práva a pravidla zápisu |
| `list_models`, `describe_model` | dostupné modely a jejich pole (s popisky v jazyce uživatele) |
| `search_read`, `read_records`, `count_records`, `name_search` | čtení |
| `aggregate` | součty po skupinách, třeba tržby pokladny po měsících |
| `get_chatter` | zprávy a změny polí u záznamu |
| `list_reports`, `get_report` | PDF reporty, odkaz ke stažení |
| `create_record`, `update_record`, `archive_record`, `delete_record` | zápis podle pravidel |
| `set_image_from_url` | stáhne obrázek z veřejné adresy do pole (fotka produktu) |
| `run_action` | povolená akce, třeba potvrzení objednávky |
| `post_note` | interní poznámka do chatteru |
| `propose_rule` | návrh pravidla zápisu, platí až po schválení v Odoo (jde i ze spojení jen pro čtení) |
| `draft_reply` | návrh odpovědi do chatteru, odešle ho jen uživatel (jde i ze spojení jen pro čtení) |

Nástroje pro zápis se klientovi nabídnou, jen když je povoluje rozsah spojení i nějaké schválené pravidlo.

- **Čtení se neukládá.** Nástroje pro čtení běží v savepointu, který se vždy vrátí zpět, takže nic
  neuloží ani při chybě.
- **Limity:**
  - výchozí limit 50 řádků, nejvýš 500;
  - odpověď do 100 000 znaků;
  - delší texty se zkracují.
- **`set_image_from_url`** stahuje jen z veřejných adres na portu 80 a 443 (ochrana proti SSRF), nejvýš
  10 MB. Přijme JPEG, PNG, GIF a WEBP, SVG ne.

## Nastavení (systémové parametry)

| parametr | výchozí | k čemu |
|---|---|---|
| `mcp_oauth_server.base_url` | prázdné | veřejná adresa, když nesedí `web.base.url` (třeba tunel pro zkoušku claude.ai) |
| `mcp_oauth_server.allow_api_keys` | `1` | přístup API klíčem se scope MCP |
| `mcp_oauth_server.allow_dcr` | `1` | dynamická registrace klientů |
| `mcp_oauth_server.cimd_hosts` | `claude.ai, claude.com, chatgpt.com` | z jakých domén smí být popis klienta (CIMD) |
| `mcp_oauth_server.redirect_uris` | claude.ai, claude.com, chatgpt.com | adresy přesměrování povolené pro DCR (`*` na konci = prefix); loopback vždy |
| `mcp_oauth_server.log_reads` | `1` | zapisovat do auditu i úspěšná čtení |
| `mcp_oauth_server.audit_days` | `90` | jak dlouho audit držet |

Adresa serveru se bere postupně:

1. `mcp_oauth_server.base_url`;
2. `web.base.url`, když je zamrzlé (`web.base.url.freeze`);
3. adresa z požadavku.

Musí přesně odpovídat adrese zadané v klientovi, jinak OAuth skončí chybou `invalid_target`.

## Tokeny a odvolání

- **Platnost:**
  - access token 1 hodina;
  - refresh token 30 dní, při každém obnovení nový;
  - starý refresh token použitý znovu po minutě odvolá celé spojení.
- **Uložení:** tokeny jen jako HMAC-SHA256 s tajemstvím databáze.
- **Připojení:** Předvolby → Zabezpečení → AI klienti (MCP), kde jde každé odvolat. Správce vidí všechna
  v Nastavení → MCP → Připojení.
- **Automatické odvolání:** nové heslo nebo deaktivace uživatele odvolá všechna jeho připojení.

## Test

```bash
odoo -d mcp_test --db-filter='^mcp_test$' -i mcp_oauth_server --test-enable --test-tags /mcp_oauth_server \
     --stop-after-init --http-port=8070 --gevent-port=8073
```

47 testů:

- pomocné funkce OAuth a ochrana proti SSRF;
- pravidla přístupu;
- návrhy pravidel od AI a jejich schválení jen člověkem;
- pokyny pro AI a vypnuté nebo omezené nástroje;
- návrhy odpovědí: neodešle je cron, odeslání a zrušení uzavře aktivitu, čištění HTML;
- nástroje z jiných addonů: vypnutí, výchozí skupiny, kolize a vadné nástroje;
- celý tok OAuth přes HTTP: DCR, souhlas, PKCE, rotace a krádež refresh tokenu, CIMD;
- API klíč;
- stažení reportu;
- jazyky: popisy nástrojů, hlášky, pokyny serveru, souhrn pravidla a stránka souhlasu česky i anglicky.

## Instalace

1. Složku `mcp_oauth_server` zkopírovat do adresáře s addony (`addons_path`). Závisí jen na `base`, `web`
   a `mail` a na knihovně `requests`, která je součástí Odoo.
2. Nainstalovat: Aplikace → MCP Server with OAuth, nebo z příkazové řádky:

   ```sh
   odoo -d <databáze> -i mcp_oauth_server --stop-after-init
   ```

3. Restartovat Odoo, aby nový kód načetly všechny workery.
4. Kontrola: `https://<adresa-odoo>/.well-known/oauth-protected-resource/api/mcp` musí vrátit
   `"resource": "https://<adresa-odoo>/api/mcp"`. Za reverzní proxy zapnout `proxy_mode`, zamrazit
   `web.base.url`, nebo nastavit `mcp_oauth_server.base_url`.
5. Nastavit pokyny pro AI a pravidla zápisu. Až pak připojit klienta.

**Aktualizace v databázi s webem.** Odoo 20 má `ir.ui.view.visibility` (modul `website`) povinné bez výchozí
hodnoty v databázi. Modul na webu nezávisí, při `-u` se proto načte dřív a nový pohled by spadl na NOT NULL.
Modul proto sloupci nastaví výchozí hodnotu `public`, stejnou jako Odoo (`models/ir_ui_view.py`). Totéž
potká každý vlastní modul bez závislosti na webu, který přidá nový pohled.

**Workery.** Každé volání nástroje drží jeden worker. Claude volá nástroje i souběžně, takže s malým počtem
workerů může dlouhý dotaz nebo PDF na chvíli zdržet ostatní uživatele.
