"""
Module : test_groups_role_inheritance.py
Rôle   : Tests de l'héritage de rôle par groupe (migration 0012, default_role).
         Vérifie create_group/update_group avec default_role, add_member, et la
         propagation _propagate_role (promotion vers le haut uniquement).

Dépend : pytest, conftest.db_test_engine (SQLite in-memory, tables groups/users)
"""

import pytest
from sqlalchemy import text

from services.groups import (
    create_group,
    update_group,
    add_member,
    get_group,
    list_groups,
    ROLE_RANK,
)


@pytest.fixture(autouse=True)
def clean(db_test_engine):
    with db_test_engine.begin() as c:
        c.execute(text("DELETE FROM group_members"))
        c.execute(text("DELETE FROM groups"))
        c.execute(text("DELETE FROM users"))
    yield


def _make_user(db_engine, username, role):
    with db_engine.begin() as c:
        c.execute(
            text("INSERT INTO users (username, role, created_at) VALUES (:u, :r, '2026-01-01')"),
            {"u": username, "r": role},
        )


def _role_of(db_engine, username):
    with db_engine.begin() as c:
        return c.execute(
            text("SELECT role FROM users WHERE username = :u"), {"u": username}
        ).scalar()


# ── create_group / default_role ───────────────────────────────────────────────

def test_create_group_with_default_role():
    g = create_group("RSSI", "Equipe securite", "red", "admin", default_role="maintainer")
    assert g["default_role"] == "maintainer"
    assert get_group(g["id"])["default_role"] == "maintainer"


def test_create_group_without_role_is_none():
    g = create_group("Lecteurs", "", "blue", "admin")
    assert g["default_role"] is None


def test_list_groups_exposes_default_role():
    create_group("G1", "", "blue", "admin", default_role="uploader")
    rows = list_groups()
    assert any(r["name"] == "G1" and r["default_role"] == "uploader" for r in rows)


# ── Propagation à l'ajout d'un membre ─────────────────────────────────────────

def test_add_member_promotes_lower_role(db_test_engine):
    _make_user(db_test_engine, "alice", "reader")
    g = create_group("Maint", "", "blue", "admin", default_role="maintainer")
    add_member(g["id"], "alice", "admin")
    assert _role_of(db_test_engine, "alice") == "maintainer"


def test_add_member_does_not_downgrade_admin(db_test_engine):
    _make_user(db_test_engine, "boss", "admin")
    g = create_group("Uploaders", "", "blue", "admin", default_role="uploader")
    add_member(g["id"], "boss", "admin")
    # admin (rang 5) > uploader (rang 3) → reste admin
    assert _role_of(db_test_engine, "boss") == "admin"


def test_add_member_to_group_without_role_keeps_role(db_test_engine):
    _make_user(db_test_engine, "carol", "reader")
    g = create_group("Plain", "", "blue", "admin")  # pas de default_role
    add_member(g["id"], "carol", "admin")
    assert _role_of(db_test_engine, "carol") == "reader"


# ── Propagation lors du changement de default_role ────────────────────────────

def test_update_group_role_propagates_to_existing_members(db_test_engine):
    _make_user(db_test_engine, "dan", "reader")
    _make_user(db_test_engine, "eve", "auditor")
    g = create_group("Team", "", "blue", "admin")
    add_member(g["id"], "dan", "admin")
    add_member(g["id"], "eve", "admin")
    # Aucun rôle hérité au départ
    assert _role_of(db_test_engine, "dan") == "reader"

    update_group(g["id"], default_role="maintainer")
    # Les deux membres montent à maintainer (tous deux < maintainer)
    assert _role_of(db_test_engine, "dan") == "maintainer"
    assert _role_of(db_test_engine, "eve") == "maintainer"


def test_update_group_role_respects_higher_existing_role(db_test_engine):
    _make_user(db_test_engine, "frank", "admin")
    g = create_group("Team2", "", "blue", "admin")
    add_member(g["id"], "frank", "admin")
    update_group(g["id"], default_role="uploader")
    # frank reste admin (uploader est inférieur)
    assert _role_of(db_test_engine, "frank") == "admin"


def test_role_rank_ordering():
    # Garde-fou : l'ordre des rangs ne doit pas régresser silencieusement
    assert ROLE_RANK["admin"] > ROLE_RANK["maintainer"] > ROLE_RANK["uploader"]
    assert ROLE_RANK["uploader"] > ROLE_RANK["auditor"] > ROLE_RANK["reader"]
