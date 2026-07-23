# File: tests/test_cov_diagnostics_checks.py
"""
Coverage tests for the individual diagnostic check categories in
`hawki.core.diagnostics.checks`. All external interactions (shutil.which,
subprocess, web3, openai/anthropic clients, filesystem home) are mocked so
these tests never touch a real system dependency, RPC endpoint or LLM.
"""

import json
import sys
import types
import unittest
from unittest import mock

from hawki.core.diagnostics.checks.ai_providers import AIProvidersCheck
from hawki.core.diagnostics.checks.budget_limits import BudgetLimitsCheck
from hawki.core.diagnostics.checks.config_storage import ConfigStorageCheck
from hawki.core.diagnostics.checks.optional_tools import OptionalToolsCheck
from hawki.core.diagnostics.checks.rpc_networks import RPCNetworksCheck
from hawki.core.diagnostics.checks.system_deps import SystemDepsCheck


# ---------------------------------------------------------------------------
# system_deps
# ---------------------------------------------------------------------------
class TestSystemDepsCheck(unittest.TestCase):
    def setUp(self):
        self.check = SystemDepsCheck()

    def test_metadata(self):
        self.assertEqual(self.check.name, "system_deps")
        self.assertEqual(self.check.category, "system")
        self.assertTrue(self.check.is_critical())

    def test_all_present_passes(self):
        def fake_run(cmd, **kwargs):
            name = cmd[0]
            outputs = {
                "forge": "forge 0.2.0",
                "solc": "solc 0.8.20",
                "git": "git version 2.40.0",
                "python3": "Python 3.12.3",
            }
            return types.SimpleNamespace(returncode=0, stdout=outputs[name], stderr="")

        with mock.patch(
            "hawki.core.diagnostics.checks.system_deps.shutil.which",
            return_value="/usr/bin/tool",
        ), mock.patch(
            "hawki.core.diagnostics.checks.system_deps.subprocess.run",
            side_effect=fake_run,
        ):
            result = self.check.run()
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.details["forge"]["status"], "ok")
        self.assertEqual(result.details["forge"]["version"], "0.2.0")

    def test_missing_dep_fails(self):
        with mock.patch(
            "hawki.core.diagnostics.checks.system_deps.shutil.which",
            return_value=None,
        ):
            result = self.check.run()
        self.assertEqual(result.status, "fail")
        self.assertIn("forge", result.details)
        self.assertEqual(result.details["forge"]["status"], "missing")
        self.assertIn("Foundry", result.fix)

    def test_nonzero_returncode_fails(self):
        def fake_run(cmd, **kwargs):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="boom")

        with mock.patch(
            "hawki.core.diagnostics.checks.system_deps.shutil.which",
            return_value="/usr/bin/tool",
        ), mock.patch(
            "hawki.core.diagnostics.checks.system_deps.subprocess.run",
            side_effect=fake_run,
        ):
            result = self.check.run()
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.details["forge"]["status"], "error")

    def test_subprocess_exception_fails(self):
        with mock.patch(
            "hawki.core.diagnostics.checks.system_deps.shutil.which",
            return_value="/usr/bin/tool",
        ), mock.patch(
            "hawki.core.diagnostics.checks.system_deps.subprocess.run",
            side_effect=OSError("timeout"),
        ):
            result = self.check.run()
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.details["forge"]["status"], "error")


# ---------------------------------------------------------------------------
# optional_tools
# ---------------------------------------------------------------------------
class TestOptionalToolsCheck(unittest.TestCase):
    def setUp(self):
        self.check = OptionalToolsCheck()

    def test_metadata(self):
        self.assertEqual(self.check.name, "optional_tools")
        self.assertEqual(self.check.category, "tools")

    def test_all_present_passes(self):
        with mock.patch(
            "hawki.core.diagnostics.checks.optional_tools.shutil.which",
            return_value="/usr/local/bin/tool",
        ):
            result = self.check.run()
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.details["slither"]["status"], "ok")

    def test_missing_tools_warns(self):
        with mock.patch(
            "hawki.core.diagnostics.checks.optional_tools.shutil.which",
            return_value=None,
        ):
            result = self.check.run()
        self.assertEqual(result.status, "warn")
        self.assertIn("slither", result.details)
        self.assertEqual(result.details["slither"]["status"], "missing")
        self.assertIn("install", result.fix.lower())


# ---------------------------------------------------------------------------
# ai_providers
# ---------------------------------------------------------------------------
def _fake_openai_module(ok=True):
    mod = types.ModuleType("openai")

    class _Client:
        def __init__(self, api_key=None):
            self.models = self

        def list(self, limit=5):
            if not ok:
                raise RuntimeError("bad key")
            return types.SimpleNamespace(data=[1, 2, 3])

    mod.OpenAI = _Client
    return mod


def _fake_anthropic_module(ok=True):
    mod = types.ModuleType("anthropic")

    class _Messages:
        def create(self, **kwargs):
            if not ok:
                raise RuntimeError("bad key")
            return types.SimpleNamespace(content="hi")

    class _Client:
        def __init__(self, api_key=None):
            self.messages = _Messages()

    mod.Anthropic = _Client
    return mod


class TestAIProvidersCheck(unittest.TestCase):
    def setUp(self):
        self.check = AIProvidersCheck()

    def test_metadata(self):
        self.assertEqual(self.check.name, "ai_providers")
        self.assertEqual(self.check.category, "ai")

    def test_no_keys_skips_and_passes(self):
        with mock.patch.dict(sys.modules), mock.patch.dict("os.environ", {}, clear=True):
            result = self.check.run({})
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.details["openai"]["status"], "skipped")
        self.assertEqual(result.details["anthropic"]["status"], "skipped")

    def test_both_keys_ok_passes(self):
        with mock.patch.dict(
            sys.modules,
            {"openai": _fake_openai_module(True), "anthropic": _fake_anthropic_module(True)},
        ), mock.patch.dict("os.environ", {}, clear=True):
            result = self.check.run({"openai_api_key": "k1", "anthropic_api_key": "k2"})
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.details["openai"]["status"], "ok")
        self.assertEqual(result.details["anthropic"]["status"], "ok")

    def test_keys_from_env_used(self):
        with mock.patch.dict(
            sys.modules,
            {"openai": _fake_openai_module(True), "anthropic": _fake_anthropic_module(True)},
        ), mock.patch.dict(
            "os.environ",
            {"OPENAI_API_KEY": "e1", "ANTHROPIC_API_KEY": "e2"},
            clear=True,
        ):
            result = self.check.run(None)
        self.assertEqual(result.status, "pass")

    def test_failing_providers_warn(self):
        with mock.patch.dict(
            sys.modules,
            {"openai": _fake_openai_module(False), "anthropic": _fake_anthropic_module(False)},
        ), mock.patch.dict("os.environ", {}, clear=True):
            result = self.check.run({"openai_api_key": "k1", "anthropic_api_key": "k2"})
        self.assertEqual(result.status, "warn")
        self.assertEqual(result.details["openai"]["status"], "error")
        self.assertEqual(result.details["anthropic"]["status"], "error")
        self.assertIn("OpenAI", result.message)


# ---------------------------------------------------------------------------
# budget_limits
# ---------------------------------------------------------------------------
class TestBudgetLimitsCheckExtra(unittest.TestCase):
    def setUp(self):
        self.check = BudgetLimitsCheck()

    def test_no_config_no_keys_warns_llm(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            result = self.check.run(None)
        self.assertEqual(result.status, "warn")
        self.assertEqual(result.details["llm_key"]["status"], "warn")

    def test_nonpositive_tokens_warns(self):
        result = self.check.run({"budget_tokens": 0, "openai_api_key": "k"})
        self.assertEqual(result.status, "warn")
        self.assertEqual(result.details["budget_tokens"]["status"], "warn")

    def test_env_key_avoids_llm_warning(self):
        with mock.patch.dict("os.environ", {"ANTHROPIC_API_KEY": "k"}, clear=True):
            result = self.check.run({"budget_attempts": 5, "budget_tokens": 5000})
        self.assertEqual(result.status, "pass")


# ---------------------------------------------------------------------------
# config_storage
# ---------------------------------------------------------------------------
class TestConfigStorageCheck(unittest.TestCase):
    def setUp(self):
        self.check = ConfigStorageCheck()

    def test_metadata(self):
        self.assertEqual(self.check.name, "config_storage")
        self.assertEqual(self.check.category, "config")
        self.assertTrue(self.check.is_critical())

    def _patch_home(self, tmp):
        return mock.patch(
            "hawki.core.diagnostics.checks.config_storage.Path.home",
            return_value=tmp,
        )

    def test_creates_missing_dir_passes(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "fakehome"
            home.mkdir()
            with self._patch_home(home):
                result = self.check.run()
            self.assertEqual(result.status, "pass")
            self.assertTrue((home / ".hawki").exists())

    def test_existing_dir_and_valid_config_passes(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            hawki_dir = home / ".hawki"
            hawki_dir.mkdir()
            (hawki_dir / "config.yaml").write_text("key: value\nother: 1\n")
            (hawki_dir / "scanned_registry.json").write_text(
                json.dumps({"entries": [1, 2, 3]})
            )
            with self._patch_home(home):
                result = self.check.run()
            self.assertEqual(result.status, "pass")
            self.assertEqual(result.details["config.yaml"]["status"], "ok")
            self.assertIn("3 entries", result.details["registry"]["message"])

    def test_invalid_yaml_fails(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            hawki_dir = home / ".hawki"
            hawki_dir.mkdir()
            (hawki_dir / "config.yaml").write_text("key: [unclosed\n")
            with self._patch_home(home):
                result = self.check.run()
            self.assertEqual(result.status, "fail")
            self.assertIn("config.yaml", result.message)

    def test_bad_registry_warns(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            hawki_dir = home / ".hawki"
            hawki_dir.mkdir()
            (hawki_dir / "scanned_registry.json").write_text("{not valid json")
            with self._patch_home(home):
                result = self.check.run()
            self.assertEqual(result.status, "warn")
            self.assertEqual(result.details["registry"]["status"], "warn")

    def test_dir_not_writable_warns(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            hawki_dir = home / ".hawki"
            hawki_dir.mkdir()
            with self._patch_home(home), mock.patch(
                "hawki.core.diagnostics.checks.config_storage.os.access",
                return_value=False,
            ):
                result = self.check.run()
            self.assertEqual(result.status, "warn")
            self.assertEqual(result.details["hawki_dir"]["status"], "warn")

    def test_mkdir_failure_fails(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "ghost"  # does not exist
            with self._patch_home(home), mock.patch(
                "hawki.core.diagnostics.checks.config_storage.Path.mkdir",
                side_effect=PermissionError("denied"),
            ):
                result = self.check.run()
            self.assertEqual(result.status, "fail")
            self.assertEqual(result.details["hawki_dir"]["status"], "fail")


# ---------------------------------------------------------------------------
# rpc_networks
# ---------------------------------------------------------------------------
class _FakeEth:
    chain_id = 1
    block_number = 12345


class _FakeW3:
    """A fake Web3 whose behaviour is controlled by class attributes."""

    connected = True
    latency_slow = False

    def __init__(self, provider):
        self.eth = _FakeEth()
        self.middleware_onion = mock.MagicMock()

    def is_connected(self):
        return type(self).connected


def _make_web3_class(connected=True):
    class _W3(_FakeW3):
        pass

    _W3.connected = connected
    # Web3 is used as Web3.HTTPProvider(...) and Web3(provider)
    _W3.HTTPProvider = staticmethod(lambda url, request_kwargs=None: ("provider", url))
    return _W3


class TestRPCNetworksCheck(unittest.TestCase):
    def setUp(self):
        self.check = RPCNetworksCheck()

    def test_metadata(self):
        self.assertEqual(self.check.name, "rpc_networks")
        self.assertEqual(self.check.category, "network")
        self.assertTrue(self.check.is_critical())

    def test_all_connected_passes(self):
        w3cls = _make_web3_class(connected=True)
        with mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.Web3", w3cls
        ):
            result = self.check.run({"chains": ["ethereum"]})
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.details["ethereum"]["status"], "ok")
        self.assertEqual(result.details["ethereum"]["chain_id"], 1)

    def test_unknown_chain_skipped(self):
        w3cls = _make_web3_class(connected=True)
        with mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.Web3", w3cls
        ):
            result = self.check.run({"chains": ["notachain"]})
        self.assertEqual(result.details["notachain"]["status"], "skipped")

    def test_all_failing_fails(self):
        w3cls = _make_web3_class(connected=False)
        with mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.Web3", w3cls
        ):
            result = self.check.run({"chains": ["ethereum", "polygon"]})
        # both fail -> failures > half -> status fail
        self.assertEqual(result.status, "fail")
        self.assertIn("ethereum", result.message)

    def test_minority_failure_warns(self):
        # ethereum connects, polygon raises -> 1 failure of 2 -> not > half -> warn
        real_w3 = _make_web3_class(connected=True)

        class _W3(real_w3):
            def is_connected(self):
                if self.eth is not None and getattr(self, "_url", None):
                    pass
                return True

        def factory(provider):
            # provider is ("provider", url); fail for polygon
            url = provider[1] if isinstance(provider, tuple) else ""
            inst = real_w3(provider)
            if "polygon" in url.lower() or "polygon" in str(url):
                raise RuntimeError("polygon down")
            return inst

        # We patch Web3 with a callable that also carries HTTPProvider.
        patched = mock.MagicMock(side_effect=factory)
        patched.HTTPProvider = lambda url, request_kwargs=None: ("provider", url)

        with mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.Web3", patched
        ), mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.get_default_rpc",
            side_effect=lambda c: f"https://rpc.{c}.example",
        ):
            result = self.check.run({"chains": ["ethereum", "polygon"]})
        self.assertEqual(result.status, "warn")
        self.assertIn("polygon", result.message)

    def test_custom_rpc_url_from_config(self):
        w3cls = _make_web3_class(connected=True)
        with mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.Web3", w3cls
        ):
            result = self.check.run(
                {"chains": ["ethereum"], "rpc_urls": {"ethereum": "https://custom.rpc"}}
            )
        self.assertEqual(result.details["ethereum"]["rpc_url"], "https://custom.rpc")

    def test_slow_rpc_warns(self):
        w3cls = _make_web3_class(connected=True)
        # Force latency > 1000ms by patching time.time to jump.
        times = iter([0.0, 2.0] * 20)
        with mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.Web3", w3cls
        ), mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.time.time",
            side_effect=lambda: next(times),
        ):
            result = self.check.run({"chains": ["ethereum"]})
        self.assertEqual(result.status, "warn")
        self.assertEqual(result.details["ethereum"]["status"], "slow")

    def test_default_chains_when_none_given(self):
        w3cls = _make_web3_class(connected=True)
        with mock.patch(
            "hawki.core.diagnostics.checks.rpc_networks.Web3", w3cls
        ):
            result = self.check.run(None)
        # Uses the built-in default chain list.
        self.assertIn("ethereum", result.details)
        self.assertEqual(result.status, "pass")


if __name__ == "__main__":
    unittest.main()
