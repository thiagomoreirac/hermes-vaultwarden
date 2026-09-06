"""Hermetic tests for the Vaultwarden secret-source plugin.

We never hit a real vault — subprocess is mocked so the suite stays
fast and offline-safe.
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import time
from pathlib import Path
from unittest import mock

import pytest

from agent.secret_sources.base import ErrorKind
from agent.secret_sources import registry

import vw_source as vw
import vw_cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_ITEM = {
    "object": "item",
    "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "name": "Hermes",
    "type": 1,
    "fields": [
        {"name": "OPENROUTER_API_KEY", "value": "sk-or-test", "type": 1},
        {"name": "ANTHROPIC_API_KEY", "value": "sk-ant-test", "type": 1},
        {"name": "123INVALID", "value": "should-be-skipped", "type": 0},
        {"name": "", "value": "also-skipped", "type": 0},
    ],
}

_FAKE_LOGIN_ITEM = {
    **_FAKE_ITEM,
    "login": {"username": "svc-hermes", "password": "hunter2"},
    "notes": "rotate quarterly",
}

_FAKE_SESSION = "fake-session-token-abc123"


def _make_ok_proc(payload=None) -> mock.MagicMock:
    proc = mock.MagicMock()
    proc.returncode = 0
    proc.stdout = json.dumps(payload if payload is not None else _FAKE_ITEM)
    proc.stderr = ""
    return proc


def _make_fail_proc(returncode=1, stderr="error msg") -> mock.MagicMock:
    proc = mock.MagicMock()
    proc.returncode = returncode
    proc.stdout = ""
    proc.stderr = stderr
    return proc


# ---------------------------------------------------------------------------
# find_bw
# ---------------------------------------------------------------------------


class TestFindBw:
    def test_finds_system_bw(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        monkeypatch.setattr(vw, "_hermes_bin_dir", lambda: tmp_path / "bin")
        result = vw.find_bw()
        assert result == Path("/usr/bin/bw")

    def test_managed_bin_wins_over_system(self, tmp_path, monkeypatch):
        managed = tmp_path / "bin" / "bw"
        managed.parent.mkdir(parents=True)
        managed.write_text("#!/bin/sh\necho fake")
        managed.chmod(0o755)
        monkeypatch.setattr(vw, "_hermes_bin_dir", lambda: tmp_path / "bin")
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        result = vw.find_bw()
        assert result == managed

    def test_returns_none_when_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vw, "_hermes_bin_dir", lambda: tmp_path / "bin")
        monkeypatch.setattr(vw.shutil, "which", lambda _: None)
        assert vw.find_bw() is None

    def test_pinned_path_wins(self, tmp_path, monkeypatch):
        pinned = tmp_path / "custom-bw"
        pinned.write_text("#!/bin/sh\necho fake")
        pinned.chmod(0o755)
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        assert vw.find_bw(str(pinned)) == pinned

    def test_broken_pin_returns_none_without_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        assert vw.find_bw(str(tmp_path / "does-not-exist")) is None


# ---------------------------------------------------------------------------
# is_valid_env_name (shared helper from base — regression sanity)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("OPENROUTER_API_KEY", True),
        ("_PRIVATE", True),
        ("MY_VAR_123", True),
        ("123INVALID", False),
        ("", False),
        ("has space", False),
        ("has-dash", False),
    ],
)
def test_is_valid_env_name(name, expected):
    assert vw.is_valid_env_name(name) is expected


# ---------------------------------------------------------------------------
# resolve_login_bindings
# ---------------------------------------------------------------------------


class TestResolveLoginBindings:
    def test_all_unset_by_default(self):
        bindings, warnings = vw.resolve_login_bindings({})
        assert bindings == {
            "username_env": None,
            "password_env": None,
            "notes_env": None,
        }
        assert warnings == []

    def test_valid_names_pass_through(self):
        cfg = {
            "username_env": "VW_USER",
            "password_env": "VW_PASS",
            "notes_env": "VW_NOTES",
        }
        bindings, warnings = vw.resolve_login_bindings(cfg)
        assert bindings == cfg
        assert warnings == []

    def test_invalid_name_warns_and_resolves_to_none(self):
        bindings, warnings = vw.resolve_login_bindings({"username_env": "bad name!"})
        assert bindings["username_env"] is None
        assert len(warnings) == 1
        assert "username_env" in warnings[0]

    def test_blank_and_whitespace_treated_as_unset(self):
        bindings, warnings = vw.resolve_login_bindings({"password_env": "   "})
        assert bindings["password_env"] is None
        assert warnings == []


# ---------------------------------------------------------------------------
# CLI hardening
# ---------------------------------------------------------------------------


class TestCliHardening:
    def test_setup_does_not_accept_session_on_argv(self):
        parser = argparse.ArgumentParser()
        vw_cli.setup_parser(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["setup", "--session", "leaky-token"])
        args = parser.parse_args(["setup", "--session-stdin", "--item-name", "Hermes"])
        assert args.session_stdin is True

    def test_override_existing_setup_default_is_false(self):
        parser = argparse.ArgumentParser()
        vw_cli.setup_parser(parser)
        args = parser.parse_args(["setup", "--item-name", "Hermes"])
        assert args.override_existing is None

    def test_setup_prefers_session_stdin_over_environment(self, monkeypatch):
        class NonTtyStringIO(io.StringIO):
            def isatty(self):
                return False

        saved_config = {}
        monkeypatch.setenv("BW_SESSION", "stale-session")
        monkeypatch.setattr(vw_cli.sys, "stdin", NonTtyStringIO("fresh-session\n"))
        monkeypatch.setattr(vw_cli.vw, "find_bw", lambda: Path("/usr/bin/bw"))
        monkeypatch.setattr(vw_cli, "_bw_version", lambda _binary: "test")
        monkeypatch.setattr(vw_cli, "_bw_current_server", lambda _binary: "")
        monkeypatch.setattr(vw_cli, "load_config", lambda: {})
        monkeypatch.setattr(vw_cli, "save_config", lambda cfg: saved_config.update(cfg))
        save_env = mock.Mock()
        monkeypatch.setattr(vw_cli, "save_env_value", save_env)
        def fake_fetch(**kwargs):
            kwargs["discovered_env_vars"].append("SAFE_API_KEY")
            return {"SAFE_API_KEY": "safe"}, []

        monkeypatch.setattr(vw_cli.vw, "fetch_vaultwarden_secrets", fake_fetch)

        args = argparse.Namespace(
            session_stdin=True,
            item_name="Hermes",
            server_url=None,
            username_env=None,
            password_env=None,
            notes_env=None,
            allowed_env_vars=None,
            override_existing=None,
        )

        assert vw_cli.cmd_setup(args) == 0
        save_env.assert_called_once_with("BW_SESSION", "fresh-session")
        vw_cfg = saved_config["secrets"]["vaultwarden"]
        assert vw_cfg["override_existing"] is False
        assert vw_cfg["allowed_env_vars"] == ["SAFE_API_KEY"]

    def test_setup_session_stdin_reads_only_first_line(self, monkeypatch):
        class SingleLineStdin:
            closed = False

            def isatty(self):
                return False

            def readline(self):
                return "fresh-session\n"

            def read(self, _size=-1):
                raise AssertionError("cmd_setup must not read beyond first stdin line")

        saved_config = {}
        monkeypatch.setattr(vw_cli.sys, "stdin", SingleLineStdin())
        monkeypatch.setattr(vw_cli.vw, "find_bw", lambda: Path("/usr/bin/bw"))
        monkeypatch.setattr(vw_cli, "_bw_version", lambda _binary: "test")
        monkeypatch.setattr(vw_cli, "_bw_current_server", lambda _binary: "")
        monkeypatch.setattr(vw_cli, "load_config", lambda: {})
        monkeypatch.setattr(vw_cli, "save_config", lambda cfg: saved_config.update(cfg))
        monkeypatch.setattr(vw_cli, "save_env_value", mock.Mock())
        monkeypatch.setattr(
            vw_cli.vw,
            "fetch_vaultwarden_secrets",
            lambda **_kwargs: ({"SAFE_API_KEY": "safe"}, []),
        )

        args = argparse.Namespace(
            session_stdin=True,
            item_name="Hermes",
            server_url=None,
            username_env=None,
            password_env=None,
            notes_env=None,
            allowed_env_vars=None,
            override_existing=None,
        )

        assert vw_cli.cmd_setup(args) == 0
        assert saved_config["secrets"]["vaultwarden"]["allowed_env_vars"] == [
            "SAFE_API_KEY"
        ]

    def test_setup_persists_explicit_allow_env_values(self, monkeypatch):
        class NonTtyStringIO(io.StringIO):
            def isatty(self):
                return False

        saved_config = {}
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw_cli.sys, "stdin", NonTtyStringIO(""))
        monkeypatch.setattr(vw_cli.vw, "find_bw", lambda: Path("/usr/bin/bw"))
        monkeypatch.setattr(vw_cli, "_bw_version", lambda _binary: "test")
        monkeypatch.setattr(vw_cli, "_bw_current_server", lambda _binary: "")
        monkeypatch.setattr(vw_cli, "load_config", lambda: {})
        monkeypatch.setattr(vw_cli, "save_config", lambda cfg: saved_config.update(cfg))
        monkeypatch.setattr(vw_cli, "save_env_value", mock.Mock())
        monkeypatch.setattr(
            vw_cli.vw,
            "fetch_vaultwarden_secrets",
            lambda **_kwargs: ({"SAFE_API_KEY": "safe"}, []),
        )

        args = argparse.Namespace(
            session_stdin=False,
            item_name="Hermes",
            server_url=None,
            username_env=None,
            password_env=None,
            notes_env=None,
            allowed_env_vars=["SAFE_API_KEY,OTHER_KEY"],
            override_existing=None,
        )

        assert vw_cli.cmd_setup(args) == 0
        vw_cfg = saved_config["secrets"]["vaultwarden"]
        assert vw_cfg["allowed_env_vars"] == ["OTHER_KEY", "SAFE_API_KEY"]

    def test_setup_preserves_existing_allowlist_without_flag(self, monkeypatch):
        class NonTtyStringIO(io.StringIO):
            def isatty(self):
                return False

        saved_config = {
            "secrets": {"vaultwarden": {"allowed_env_vars": ["SAFE_API_KEY"]}}
        }
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw_cli.sys, "stdin", NonTtyStringIO(""))
        monkeypatch.setattr(vw_cli.vw, "find_bw", lambda: Path("/usr/bin/bw"))
        monkeypatch.setattr(vw_cli, "_bw_version", lambda _binary: "test")
        monkeypatch.setattr(vw_cli, "_bw_current_server", lambda _binary: "")
        monkeypatch.setattr(vw_cli, "load_config", lambda: saved_config)
        monkeypatch.setattr(vw_cli, "save_config", lambda cfg: saved_config.update(cfg))
        monkeypatch.setattr(vw_cli, "save_env_value", mock.Mock())

        def fake_fetch(**kwargs):
            kwargs["discovered_env_vars"].extend(["SAFE_API_KEY", "NEW_API_KEY"])
            return {"SAFE_API_KEY": "safe", "NEW_API_KEY": "new"}, []

        monkeypatch.setattr(vw_cli.vw, "fetch_vaultwarden_secrets", fake_fetch)

        args = argparse.Namespace(
            session_stdin=False,
            item_name="Hermes",
            server_url=None,
            username_env=None,
            password_env=None,
            notes_env=None,
            allowed_env_vars=None,
            override_existing=None,
        )

        assert vw_cli.cmd_setup(args) == 0
        vw_cfg = saved_config["secrets"]["vaultwarden"]
        assert vw_cfg["allowed_env_vars"] == ["SAFE_API_KEY"]

    def test_sync_passes_configured_allowed_env_vars(self, monkeypatch):
        fetch = mock.Mock(return_value=({"SAFE_API_KEY": "safe"}, []))
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(
            vw_cli,
            "load_config",
            lambda: {
                "secrets": {
                    "vaultwarden": {
                        "enabled": True,
                        "item_name": "Hermes",
                        "allowed_env_vars": ["SAFE_API_KEY"],
                    }
                }
            },
        )
        monkeypatch.setattr(vw_cli.vw, "find_bw", lambda _pin=None: Path("/usr/bin/bw"))
        monkeypatch.setattr(vw_cli, "run_secret_cli", lambda *_args, **_kwargs: _make_ok_proc())
        monkeypatch.setattr(vw_cli.vw, "fetch_vaultwarden_secrets", fetch)

        assert vw_cli.cmd_sync(argparse.Namespace(apply=False)) == 0
        assert fetch.call_args.kwargs["allowed_env_vars"] == {"SAFE_API_KEY"}


# ---------------------------------------------------------------------------
# fetch_vaultwarden_secrets
# ---------------------------------------------------------------------------


class TestFetchVaultwardenSecrets:
    def setup_method(self):
        vw._CACHE.clear()

    def test_returns_parsed_fields(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        assert secrets["ANTHROPIC_API_KEY"] == "sk-ant-test"
        assert "123INVALID" not in secrets
        assert any("123INVALID" in w for w in warnings)

    def test_allowed_env_vars_filters_custom_fields(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                allowed_env_vars=["OPENROUTER_API_KEY"],
            )
        assert secrets == {"OPENROUTER_API_KEY": "sk-or-test"}
        assert any("ANTHROPIC_API_KEY" in w and "allowed_env_vars" in w for w in warnings)

    def test_malformed_allowed_env_vars_fails_closed(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                allowed_env_vars={"not": "a list"},
            )
        assert secrets == {}
        assert any("allowed_env_vars must be a list" in w for w in warnings)

    def test_blocklisted_env_vars_are_never_exported(self, tmp_path):
        item = {
            **_FAKE_ITEM,
            "fields": [
                {
                    "name": "OPENAI_BASE_URL",
                    "value": "https://evil.invalid",
                    "type": 1,
                },
                {"name": "HTTPS_PROXY", "value": "http://evil.invalid", "type": 1},
                {"name": "HOME", "value": "/tmp/evil-home", "type": 1},
                {"name": "SAFE_API_KEY", "value": "safe", "type": 1},
            ],
        }
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                allowed_env_vars=["OPENAI_BASE_URL", "HTTPS_PROXY", "SAFE_API_KEY"],
            )
        assert secrets == {"SAFE_API_KEY": "safe"}
        assert any("OPENAI_BASE_URL" in w and "blocked" in w for w in warnings)
        assert any("HTTPS_PROXY" in w and "blocked" in w for w in warnings)
        assert any("HOME" in w and "blocked" in w for w in warnings)

    def test_child_env_is_minimal_and_session_not_in_argv(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        argv = mock_run.call_args.args[0]
        assert "--session" not in argv
        assert _FAKE_SESSION not in argv
        assert argv[-2:] == ["--", "Hermes"]
        child_env = mock_run.call_args.kwargs["env"]
        assert child_env["BW_SESSION"] == _FAKE_SESSION
        # allowlisted env only — no wholesale os.environ copy
        assert "HERMES_TEST_CANARY" not in child_env

    def test_raises_on_empty_session(self):
        with pytest.raises(RuntimeError, match="session token is empty"):
            vw.fetch_vaultwarden_secrets(
                session="",
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
            )

    def test_raises_on_empty_item_name(self):
        with pytest.raises(RuntimeError, match="item_name is empty"):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
            )

    def test_raises_when_bw_fails(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_fail_proc(1, "Not logged in")):
            with pytest.raises(RuntimeError, match="bw exited 1"):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=False,
                    home_path=tmp_path,
                )

    def test_raises_when_bw_not_found(self, monkeypatch):
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: None)
        with pytest.raises(RuntimeError, match="bw binary not found"):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=None,
                use_cache=False,
            )

    def test_in_process_cache_prevents_second_subprocess_call(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            for _ in range(2):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=True,
                    cache_ttl_seconds=300,
                    home_path=tmp_path,
                )
        assert mock_run.call_count == 1

    def test_disk_cache_survives_process_cache_clear(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
            vw._CACHE.clear()
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        assert mock_run.call_count == 1
        assert "OPENROUTER_API_KEY" in secrets

    def test_expired_disk_cache_triggers_refetch(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                cache_ttl_seconds=1,
                use_cache=True,
                home_path=tmp_path,
            )
            vw._CACHE.clear()
            cache_file = vw._disk_cache_path(tmp_path)
            payload = json.loads(cache_file.read_text())
            payload["fetched_at"] = time.time() - 10
            cache_file.write_text(json.dumps(payload))

            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                cache_ttl_seconds=1,
                use_cache=True,
                home_path=tmp_path,
            )
        assert mock_run.call_count == 2

    def test_item_with_no_fields_returns_empty_with_warning(self, tmp_path):
        item = {**_FAKE_ITEM, "fields": []}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        assert secrets == {}
        assert any("fields" in w for w in warnings)

    def test_raises_on_non_json_output(self, tmp_path):
        proc = mock.MagicMock()
        proc.returncode = 0
        proc.stdout = "not json"
        proc.stderr = ""
        with mock.patch("subprocess.run", return_value=proc):
            with pytest.raises(RuntimeError, match="non-JSON"):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=False,
                    home_path=tmp_path,
                )

    def test_login_bindings_opt_in(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                username_env="SVC_USER",
                password_env="SVC_PASSWORD",
                notes_env="SVC_NOTES",
            )
        assert secrets["SVC_USER"] == "svc-hermes"
        assert secrets["SVC_PASSWORD"] == "hunter2"
        assert secrets["SVC_NOTES"] == "rotate quarterly"
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        assert not any("SVC_" in w for w in warnings)

    def test_login_bindings_default_off(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        assert "SVC_USER" not in secrets
        assert "hunter2" not in secrets.values()

    def test_login_binding_missing_value_warns(self, tmp_path):
        item = {**_FAKE_ITEM, "login": {}, "notes": ""}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                username_env="SVC_USER",
                notes_env="SVC_NOTES",
            )
        assert "SVC_USER" not in secrets
        assert any("login.username" in w for w in warnings)
        assert any("notes" in w for w in warnings)

    def test_login_binding_collision_with_custom_field_warns(self, tmp_path):
        item = {
            **_FAKE_ITEM,
            "fields": [{"name": "SVC_USER", "value": "from-field", "type": 1}],
            "login": {"username": "from-login"},
        }
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                username_env="SVC_USER",
            )
        assert secrets["SVC_USER"] == "from-login"
        assert any("both a custom field" in w for w in warnings)

    def test_cache_key_distinguishes_login_bindings(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
                username_env="SVC_USER",
            )
        assert mock_run.call_count == 2
        assert secrets["SVC_USER"] == "svc-hermes"

    def test_cache_key_distinguishes_allowed_env_vars(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            first, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
                allowed_env_vars=["OPENROUTER_API_KEY"],
            )
            second, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
                allowed_env_vars=["ANTHROPIC_API_KEY"],
            )
        assert mock_run.call_count == 2
        assert first == {"OPENROUTER_API_KEY": "sk-or-test"}
        assert second == {"ANTHROPIC_API_KEY": "sk-ant-test"}

    def test_timeout_raises_runtime_error(self, tmp_path):
        with mock.patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("bw", 30)
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=False,
                    home_path=tmp_path,
                )


# ---------------------------------------------------------------------------
# VaultwardenSource.fetch — the SecretSource contract surface
# ---------------------------------------------------------------------------


class TestVaultwardenSourceFetch:
    def setup_method(self):
        vw._CACHE.clear()
        self.source = vw.VaultwardenSource()

    def test_disabled_by_default(self):
        assert self.source.is_enabled({}) is False
        assert self.source.is_enabled({"enabled": False}) is False

    def test_missing_session_env_reports_not_configured(self, monkeypatch):
        monkeypatch.delenv("BW_SESSION", raising=False)
        result = self.source.fetch({"enabled": True, "item_name": "Hermes"}, Path("/tmp"))
        assert not result.ok
        assert "BW_SESSION" in result.error
        assert result.error_kind is ErrorKind.NOT_CONFIGURED
        assert result.secrets == {}

    def test_missing_item_name_reports_not_configured(self, monkeypatch):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        result = self.source.fetch({"enabled": True}, Path("/tmp"))
        assert not result.ok
        assert "item_name" in result.error
        assert result.error_kind is ErrorKind.NOT_CONFIGURED

    def test_missing_binary_reports_binary_missing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: None)
        result = self.source.fetch(
            {"enabled": True, "item_name": "Hermes"}, tmp_path
        )
        assert not result.ok
        assert "not found" in result.error
        assert result.error_kind is ErrorKind.BINARY_MISSING

    def test_fetch_error_classified(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch(
            "subprocess.run", return_value=_make_fail_proc(1, "Session expired")
        ):
            result = self.source.fetch(
                {"enabled": True, "item_name": "Hermes"}, tmp_path
            )
        assert not result.ok
        assert "Session expired" in result.error
        assert result.error_kind is ErrorKind.AUTH_EXPIRED

    def test_fetch_returns_secrets_without_touching_environ(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            result = self.source.fetch(
                {"enabled": True, "item_name": "Hermes"}, tmp_path
            )
        assert result.ok
        assert result.secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        import os

        assert "OPENROUTER_API_KEY" not in os.environ

    def test_login_bindings_exported_via_config(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            result = self.source.fetch(
                {
                    "enabled": True,
                    "item_name": "Hermes",
                    "username_env": "SVC_USER",
                    "password_env": "SVC_PASSWORD",
                },
                tmp_path,
            )
        assert result.ok
        assert result.secrets["SVC_USER"] == "svc-hermes"
        assert result.secrets["SVC_PASSWORD"] == "hunter2"
        assert "SVC_NOTES" not in result.secrets

    def test_invalid_login_binding_name_warns_and_is_ignored(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            result = self.source.fetch(
                {
                    "enabled": True,
                    "item_name": "Hermes",
                    "username_env": "not a name",
                },
                tmp_path,
            )
        assert result.ok
        assert "not a name" not in result.secrets
        assert any("not a valid" in w for w in result.warnings)

    def test_protected_env_vars_follows_config(self):
        assert self.source.protected_env_vars({}) == frozenset({"BW_SESSION"})
        assert self.source.protected_env_vars(
            {"session_env": "MY_BW_TOKEN"}
        ) == frozenset({"MY_BW_TOKEN"})
        # invalid name falls back to the default rather than exporting junk
        assert self.source.protected_env_vars(
            {"session_env": "not a name"}
        ) == frozenset({"BW_SESSION"})

    def test_override_existing_defaults_false(self):
        assert self.source.override_existing({}) is False
        assert self.source.override_existing({"override_existing": True}) is True


@pytest.mark.parametrize(
    "message, expected",
    [
        ("bw timed out after 30s", ErrorKind.TIMEOUT),
        ("failed to invoke bw: No such file", ErrorKind.BINARY_MISSING),
        ("bw exited 1: Session expired", ErrorKind.AUTH_EXPIRED),
        ("bw exited 1: Vault is locked.", ErrorKind.AUTH_EXPIRED),
        ("bw exited 1: You are not logged in.", ErrorKind.AUTH_EXPIRED),
        ("bw exited 1: Not found.", ErrorKind.REF_INVALID),
        ("bw exited 1: connection refused", ErrorKind.NETWORK),
        ("bw returned non-JSON output: x", ErrorKind.INTERNAL),
    ],
)
def test_classify_bw_error(message, expected):
    assert vw._classify_bw_error(message) is expected


# ---------------------------------------------------------------------------
# Orchestrator round-trip — apply semantics now live in registry.apply_all
# ---------------------------------------------------------------------------


class TestOrchestratedApply:
    def setup_method(self):
        vw._CACHE.clear()
        registry._reset_registry_for_tests()
        registry.register_source(vw.VaultwardenSource())

    def teardown_method(self):
        registry._reset_registry_for_tests()

    def _apply(self, tmp_path, environ, cfg_extra=None):
        cfg = {"enabled": True, "item_name": "Hermes", **(cfg_extra or {})}
        return registry.apply_all({"vaultwarden": cfg}, tmp_path, environ=environ)

    def test_applies_new_secrets(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        environ = {}
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            report = self._apply(tmp_path, environ)
        assert environ["OPENROUTER_API_KEY"] == "sk-or-test"
        assert report.provenance["OPENROUTER_API_KEY"].source == "vaultwarden"
        assert report.provenance["OPENROUTER_API_KEY"].shape == "bulk"

    def test_skips_existing_when_override_false(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        environ = {"OPENROUTER_API_KEY": "existing-value"}
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            report = self._apply(tmp_path, environ)
        assert environ["OPENROUTER_API_KEY"] == "existing-value"
        sr = report.sources[0]
        assert "OPENROUTER_API_KEY" in sr.skipped_existing
        assert "ANTHROPIC_API_KEY" in sr.applied

    def test_overrides_existing_when_flag_set(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        environ = {"OPENROUTER_API_KEY": "old-value"}
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            report = self._apply(
                tmp_path, environ, cfg_extra={"override_existing": True}
            )
        assert environ["OPENROUTER_API_KEY"] == "sk-or-test"
        assert report.provenance["OPENROUTER_API_KEY"].overrode_env is True

    def test_session_env_itself_never_overwritten(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        item = {
            **_FAKE_ITEM,
            "fields": [
                {"name": "BW_SESSION", "value": "should-not-apply", "type": 1},
                {"name": "SOME_KEY", "value": "val", "type": 1},
            ],
        }
        environ = {"BW_SESSION": _FAKE_SESSION}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            report = self._apply(
                tmp_path, environ, cfg_extra={"override_existing": True}
            )
        assert environ["BW_SESSION"] == _FAKE_SESSION
        sr = report.sources[0]
        assert "BW_SESSION" in sr.skipped_protected
        assert "SOME_KEY" in sr.applied

    def test_fetch_error_does_not_break_pass(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch(
            "subprocess.run", return_value=_make_fail_proc(1, "Session expired")
        ):
            report = self._apply(tmp_path, {})
        assert not report.applied_any
        assert not report.sources[0].result.ok


# ---------------------------------------------------------------------------
# Disk cache format
# ---------------------------------------------------------------------------


class TestDiskCache:
    def setup_method(self):
        vw._CACHE.clear()

    def test_disk_cache_written_with_mode_0600(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        cache_path = vw._disk_cache_path(tmp_path)
        assert cache_path.exists()
        mode = cache_path.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    def test_cache_key_prefixed_with_vw(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        payload = json.loads(vw._disk_cache_path(tmp_path).read_text())
        assert payload["key"].startswith("vw|")
        assert _FAKE_SESSION not in payload["key"]

    def test_zero_ttl_writes_no_cache_file(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                cache_ttl_seconds=0,
                use_cache=True,
                home_path=tmp_path,
            )
        assert not vw._disk_cache_path(tmp_path).exists()

    def test_reset_cache_for_tests_clears_both_layers(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        assert vw._CACHE
        vw._reset_cache_for_tests(tmp_path)
        assert not vw._CACHE
        assert not vw._disk_cache_path(tmp_path).exists()
