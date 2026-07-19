# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_http_retry.py
Rôle   : services/http_retry.py:fetch_url() — retry avec backoff court sur
         aléa réseau transitoire pour les fetchs de sync d'index.

         Avant ce module : un timeout ou une erreur 5xx ponctuelle sur une
         seule requête marquait directement la source "error" jusqu'au
         prochain cron/déclenchement manuel — aucune distinction entre
         "source déplacée définitivement" (404/403) et "aléa réseau
         transitoire" (souvent résolu en réessayant quelques secondes
         après).

Dépend : pytest, unittest.mock.patch. `_sleep` est toujours patché via
         patch("services.http_retry.time.sleep") (jamais le paramètre
         _sleep directement) pour vérifier que le patch au niveau module
         fonctionne réellement — piège trouvé en écrivant ce correctif :
         un défaut de paramètre _sleep=time.sleep aurait figé la référence
         à l'import, invisible à un patch ultérieur.
"""
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from services.http_retry import fetch_url


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="http://x", code=code, msg="err", hdrs=None, fp=None)


def _mock_resp(data: bytes):
    m = MagicMock()
    m.__enter__ = MagicMock(return_value=m)
    m.__exit__ = MagicMock(return_value=False)
    m.read = MagicMock(return_value=data)
    return m


class TestFetchUrlSuccess:
    def test_first_try_success_no_sleep_no_retry(self):
        with patch("urllib.request.urlopen", return_value=_mock_resp(b"data")) as mock_open, \
             patch("services.http_retry.time.sleep") as mock_sleep:
            result = fetch_url("http://example.test/x")
        assert result == b"data"
        assert mock_open.call_count == 1
        mock_sleep.assert_not_called()


class TestFetchUrlRetryableErrors:
    def test_url_error_retries_then_succeeds(self):
        with patch("urllib.request.urlopen",
                    side_effect=[urllib.error.URLError("timeout"), _mock_resp(b"ok")]) as mock_open, \
             patch("services.http_retry.time.sleep") as mock_sleep:
            result = fetch_url("http://example.test/x")
        assert result == b"ok"
        assert mock_open.call_count == 2
        mock_sleep.assert_called_once_with(2.0)

    def test_http_500_is_retried(self):
        with patch("urllib.request.urlopen",
                    side_effect=[_http_error(500), _mock_resp(b"ok")]), \
             patch("services.http_retry.time.sleep") as mock_sleep:
            result = fetch_url("http://example.test/x")
        assert result == b"ok"
        mock_sleep.assert_called_once()

    def test_http_429_is_retried(self):
        with patch("urllib.request.urlopen",
                    side_effect=[_http_error(429), _mock_resp(b"ok")]), \
             patch("services.http_retry.time.sleep"):
            result = fetch_url("http://example.test/x")
        assert result == b"ok"

    def test_exhausts_retries_then_raises_last_exception(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")) as mock_open, \
             patch("services.http_retry.time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.URLError):
                fetch_url("http://example.test/x", max_retries=2)
        assert mock_open.call_count == 3  # tentative initiale + 2 retries
        assert mock_sleep.call_count == 2

    def test_backoff_schedule_is_2s_then_5s(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")), \
             patch("services.http_retry.time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.URLError):
                fetch_url("http://example.test/x", max_retries=2, backoff_seconds=(2.0, 5.0))
        assert [c.args[0] for c in mock_sleep.call_args_list] == [2.0, 5.0]


class TestFetchUrlNonRetryableErrors:
    @pytest.mark.parametrize("code", [400, 401, 403, 404, 410])
    def test_client_errors_raise_immediately_without_retry(self, code):
        with patch("urllib.request.urlopen", side_effect=_http_error(code)) as mock_open, \
             patch("services.http_retry.time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                fetch_url("http://example.test/x")
        assert exc_info.value.code == code
        assert mock_open.call_count == 1  # jamais retenté
        mock_sleep.assert_not_called()


class TestFetchUrlNoRetriesConfigured:
    def test_max_retries_zero_tries_exactly_once(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")) as mock_open, \
             patch("services.http_retry.time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.URLError):
                fetch_url("http://example.test/x", max_retries=0)
        assert mock_open.call_count == 1
        mock_sleep.assert_not_called()
