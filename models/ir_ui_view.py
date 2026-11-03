# -*- coding: utf-8 -*-
from odoo import models
from odoo.tools import SQL


class IrUiView(models.Model):
    _inherit = "ir.ui.view"

    def init(self):
        """Obejít past Odoo 20 při aktualizaci modulu (-u) v databázi s webem.

        Modul `website` má `ir.ui.view.visibility` povinné (NOT NULL) bez výchozí hodnoty v databázi.
        Tenhle modul na webu nezávisí, při aktualizaci se proto načte dřív a jeho nové pohledy by Odoo
        vložilo bez sloupce `visibility`, což spadne. Výchozí hodnota v databázi je stejná jako v Odoo.
        """
        self.env.cr.execute(SQL(
            """SELECT 1 FROM information_schema.columns
               WHERE table_name = 'ir_ui_view' AND column_name = 'visibility' AND column_default IS NULL"""
        ))
        if self.env.cr.fetchone():
            self.env.cr.execute(SQL("ALTER TABLE ir_ui_view ALTER COLUMN visibility SET DEFAULT 'public'"))
