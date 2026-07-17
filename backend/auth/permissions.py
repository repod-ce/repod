"""
Catalogue de permissions et mapping des rôles built-in.
"""

ALL_PERMISSIONS: set[str] = {
    "cve.view",
    "cve.decide",
    "pkg.upload",
    "pkg.import",
    "pkg.delete",
    "pkg.promote",
    "user.manage",
    "group.manage",
    "role.manage",
    "audit.read",
    "settings.admin",
    "system.backup",
    "inventory.read",
    "inventory.scan",
    "deploy.run",
}

PERMISSION_LABELS: dict[str, str] = {
    "cve.view":       "Voir les CVE",
    "cve.decide":     "Prendre des décisions CVE",
    "pkg.upload":     "Déposer des paquets",
    "pkg.import":     "Importer des paquets",
    "pkg.delete":     "Supprimer des paquets",
    "pkg.promote":    "Promouvoir des paquets",
    "user.manage":    "Gérer les utilisateurs",
    "group.manage":   "Gérer les groupes",
    "role.manage":    "Gérer les rôles",
    "audit.read":     "Lire les logs d'audit",
    "settings.admin": "Administrer les paramètres",
    "system.backup":  "Gérer les sauvegardes",
    "inventory.read": "Voir l'inventaire machines",
    "inventory.scan": "Déclencher des scans inventaire",
    "deploy.run":     "Déployer des paquets sur les machines",
}

PERMISSION_CATEGORIES: dict[str, list[str]] = {
    "Sécurité CVE": ["cve.view", "cve.decide"],
    "Paquets":      ["pkg.upload", "pkg.import", "pkg.delete", "pkg.promote"],
    "Administration": ["user.manage", "group.manage", "role.manage", "settings.admin", "system.backup"],
    "Audit":        ["audit.read"],
    "Inventaire":   ["inventory.read", "inventory.scan", "deploy.run"],
}

BUILTIN_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": ALL_PERMISSIONS,
    "maintainer": {
        "cve.view", "cve.decide",
        "pkg.upload", "pkg.import", "pkg.delete", "pkg.promote",
        "audit.read",
        "inventory.read", "inventory.scan", "deploy.run",
    },
    "uploader": {"pkg.upload", "pkg.import"},
    "auditor":  {"cve.view", "audit.read", "inventory.read"},
    "reader":   {"cve.view"},
}
