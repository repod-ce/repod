"""
Module : test_email_templates.py
Rôle   : Tests du moteur de templates email Jinja2 (services/email_templates.py).
         Vérifie le rendu, l'injection du contexte commun (timestamp, app_url),
         le fallback "default", le preview avec données fictives, save/reset.

Dépend : pytest, jinja2 ; templates écrits dans un répertoire temporaire isolé.
"""

import importlib
import os

import pytest


@pytest.fixture()
def templates(tmp_path, monkeypatch):
    monkeypatch.setenv("EMAIL_TEMPLATES_DIR", str(tmp_path / "email"))
    import services.email_templates as et
    importlib.reload(et)
    return et


def test_defaults_are_seeded(templates):
    names = {t["name"] for t in templates.list_templates()}
    assert "base" in names
    assert "pending_review" in names
    assert "security_decision" in names
    assert "default" in names


def test_render_injects_common_context(templates, monkeypatch):
    monkeypatch.setattr(
        "services.settings.get_settings",
        lambda: {"app_name": "RepoD-Test", "app_url": "https://repod.example.com/"},
    )
    subject, html = templates.render_email_template("security_decision", {
        "package": "openssl", "version": "3.0.14-1",
        "action": "accept_risk", "decided_by": "rssi", "justification": "ok",
    })
    assert "openssl" in subject
    assert "RepoD-Test" in html          # instance_name injecté
    assert "https://repod.example.com" in html  # app_url injecté (sans / final)
    assert "Risque accepte" in html       # action_label résolu


def test_unknown_template_falls_back_to_default(templates):
    subject, html = templates.render_email_template("evenement_inexistant_xyz", {"foo": "bar"})
    assert "EVENEMENT_INEXISTANT_XYZ" in subject or "evenement_inexistant_xyz" in subject.lower()
    assert html  # non vide


def test_preview_with_sample_data_does_not_raise(templates):
    for name in ["pending_review", "escalation", "sla_overdue", "patch_available",
                 "security_decision", "scheduler_job_failed"]:
        html = templates.preview_template(name)
        assert html and "<" in html


def test_save_and_get_template(templates):
    body = "{% set title = 'Custom' %}<p>Mon template {{ package }}</p>"
    templates.save_template("pending_review", body, subject="[Custom] {{ package }}")
    tpl = templates.get_template("pending_review")
    assert tpl["body"] == body
    assert tpl["subject"] == "[Custom] {{ package }}"
    # marqué comme personnalisé dans la liste
    info = next(t for t in templates.list_templates() if t["name"] == "pending_review")
    assert info["is_customized"] is True


def test_reset_template_restores_default(templates):
    templates.save_template("escalation", "<p>modifié</p>", subject="x")
    restored = templates.reset_template("escalation")
    assert "modifié" not in restored["body"]
    assert "Escalade" in restored["body"] or "escalade" in restored["body"].lower()


def test_preview_with_custom_body(templates):
    html = templates.preview_template("pending_review", body="<p>{{ package }} / {{ timestamp }}</p>")
    assert "openssl" in html        # depuis les données fictives
