# File: tests/sandbox/test_cov_sandbox_manager.py
"""Coverage tests for SandboxManager with a fully-mocked docker client.

No real container, forge, anvil, solc or network is ever touched: docker.from_env
and DockerConfig are patched at construction, and the container object is a
MagicMock whose exec_run returns canned (exit_code, bytes) tuples.
"""
import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hawki.core.exploit_sandbox import sandbox_manager as sm
from hawki.core.exploit_sandbox.sandbox_manager import SandboxManager


@pytest.fixture
def make_manager(tmp_path):
    """Factory building a SandboxManager with docker fully mocked out."""
    def _make(repo=None, scripts_dir=None):
        repo = Path(repo) if repo else tmp_path / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        with patch.object(sm, "DockerConfig"), \
             patch.object(sm.docker, "from_env"):
            mgr = SandboxManager(repo, attack_scripts_dir=scripts_dir)
        mgr.client = MagicMock()
        return mgr
    return _make


def _fake_start(mgr, ws, container):
    """Return a callable standing in for _start_container."""
    def _start():
        mgr.container = container
        mgr.workspace_dir = str(ws)
        return container
    return _start


# ---------------------------------------------------------------------------
# _parse_result (pure text parsing)
# ---------------------------------------------------------------------------

def test_parse_result_success_json(make_manager):
    mgr = make_manager()
    out = (
        "some log line\n"
        '{"success": true, "before_balance": 100, "after_balance": 0, '
        '"gas_used": 21000, "transaction_hash": "0xabc"}'
    )
    res = mgr._parse_result(out, "reentrancy_attack.py")
    assert res["attack_name"] == "reentrancy_attack.py"
    assert res["success"] is True
    assert res["before_balance"] == 100
    assert res["after_balance"] == 0
    assert res["gas_used"] == 21000
    assert res["transaction_hash"] == "0xabc"
    assert res["logs"] == out


def test_parse_result_garbage(make_manager):
    mgr = make_manager()
    out = "no json here\njust noise"
    res = mgr._parse_result(out, "x.py")
    assert res["success"] is False
    assert res["before_balance"] == 0
    assert res["logs"] == out


def test_parse_result_picks_last_dict_skips_nondict(make_manager):
    mgr = make_manager()
    # Last line is a JSON list (not a dict) -> skipped; earlier dict is used.
    out = '{"success": true, "gas_used": 5}\n[1, 2, 3]'
    res = mgr._parse_result(out, "x.py")
    assert res["success"] is True
    assert res["gas_used"] == 5


def test_parse_result_empty(make_manager):
    mgr = make_manager()
    res = mgr._parse_result("", "x.py")
    assert res["success"] is False


# ---------------------------------------------------------------------------
# _discover_attack_scripts
# ---------------------------------------------------------------------------

def test_discover_scripts_missing_dir(make_manager, tmp_path):
    mgr = make_manager(scripts_dir=tmp_path / "does_not_exist")
    assert mgr._discover_attack_scripts() == []


def test_discover_scripts_excludes_init(make_manager, tmp_path):
    d = tmp_path / "scripts"
    d.mkdir()
    (d / "a_attack.py").touch()
    (d / "b_attack.py").touch()
    (d / "__init__.py").touch()
    mgr = make_manager(scripts_dir=d)
    scripts = mgr._discover_attack_scripts()
    assert sorted(s.name for s in scripts) == ["a_attack.py", "b_attack.py"]


# ---------------------------------------------------------------------------
# _read_workspace_text / _write_workspace_file
# ---------------------------------------------------------------------------

def test_read_workspace_text(make_manager, tmp_path):
    mgr = make_manager()
    ws = tmp_path / "ws"
    ws.mkdir()
    mgr.workspace_dir = str(ws)
    (ws / "anvil.log").write_text("boot ok")
    assert mgr._read_workspace_text("anvil.log") == "boot ok"
    assert mgr._read_workspace_text("missing.log") == ""


def test_read_workspace_text_swallows_errors(make_manager):
    mgr = make_manager()
    mgr.workspace_dir = None  # Path(None) raises -> caught, returns ""
    assert mgr._read_workspace_text("anvil.log") == ""


def test_write_workspace_file(make_manager, tmp_path):
    mgr = make_manager()
    ws = tmp_path / "ws"
    ws.mkdir()
    mgr.workspace_dir = str(ws)
    src = tmp_path / "exploit.py"
    src.write_text("print('hi')")
    target = mgr._write_workspace_file("exploit.py", src)
    assert target == "/workspace/exploit.py"
    assert (ws / "exploit.py").read_text() == "print('hi')"


# ---------------------------------------------------------------------------
# _start_container / _start_evm_node / _wait_for_rpc
# ---------------------------------------------------------------------------

def test_start_container(make_manager, tmp_path):
    mgr = make_manager(repo=tmp_path / "repo")
    container = MagicMock()
    container.id = "abcdef123456deadbeef"
    mgr.client.containers.run.return_value = container
    try:
        c = mgr._start_container()
        assert c is container
        ws = Path(mgr.workspace_dir)
        assert (ws / "deploy.py").exists()
        kwargs = mgr.client.containers.run.call_args.kwargs
        assert kwargs["image"] == mgr.docker_cfg.IMAGE_NAME
        assert kwargs["detach"] is True
        binds = {v["bind"] for v in kwargs["volumes"].values()}
        assert {"/repo", "/attack_scripts", "/workspace"} <= binds
    finally:
        if mgr.workspace_dir:
            shutil.rmtree(mgr.workspace_dir, ignore_errors=True)


def test_start_evm_node(make_manager):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr._start_evm_node()
    args, kwargs = mgr.container.exec_run.call_args
    assert kwargs["detach"] is True
    assert "anvil" in args[0][2]


def test_wait_for_rpc_success(make_manager):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.container.exec_run.return_value = (0, b"")
    with patch.object(sm.time, "time", side_effect=[0.0, 0.1]), \
         patch.object(sm.time, "sleep"):
        assert mgr._wait_for_rpc(timeout=5) is True


def test_wait_for_rpc_timeout(make_manager):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.container.exec_run.return_value = (1, b"")
    with patch.object(sm.time, "time", side_effect=[100.0, 100.5, 102.0]), \
         patch.object(sm.time, "sleep"):
        assert mgr._wait_for_rpc(timeout=1) is False


# ---------------------------------------------------------------------------
# _deploy_contracts (all branches)
# ---------------------------------------------------------------------------

def test_deploy_contracts_rpc_not_ready(make_manager):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.workspace_dir = "/nonexistent"
    with patch.object(mgr, "_start_evm_node"), \
         patch.object(mgr, "_wait_for_rpc", return_value=False), \
         patch.object(mgr, "_read_workspace_text", return_value="boom"):
        assert mgr._deploy_contracts() is None


def test_deploy_contracts_deploy_nonzero(make_manager):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.container.exec_run.return_value = (1, b"deploy error")
    mgr.workspace_dir = "/tmp"
    with patch.object(mgr, "_start_evm_node"), \
         patch.object(mgr, "_wait_for_rpc", return_value=True):
        assert mgr._deploy_contracts() is None


def test_deploy_contracts_missing_addresses_file(make_manager, tmp_path):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.container.exec_run.return_value = (0, b"ok")
    ws = tmp_path / "ws"
    ws.mkdir()
    mgr.workspace_dir = str(ws)
    with patch.object(mgr, "_start_evm_node"), \
         patch.object(mgr, "_wait_for_rpc", return_value=True):
        assert mgr._deploy_contracts() is None


def test_deploy_contracts_empty_addresses(make_manager, tmp_path):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.container.exec_run.return_value = (0, b"ok")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "addresses.json").write_text(json.dumps({}))
    mgr.workspace_dir = str(ws)
    with patch.object(mgr, "_start_evm_node"), \
         patch.object(mgr, "_wait_for_rpc", return_value=True):
        assert mgr._deploy_contracts() is None


def test_deploy_contracts_success(make_manager, tmp_path):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.container.exec_run.return_value = (0, b"deployed")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "addresses.json").write_text(json.dumps({"Vault": "0x1"}))
    mgr.workspace_dir = str(ws)
    with patch.object(mgr, "_start_evm_node"), \
         patch.object(mgr, "_wait_for_rpc", return_value=True):
        addrs = mgr._deploy_contracts()
    assert addrs == {"Vault": "0x1"}


# ---------------------------------------------------------------------------
# _run_attack_script
# ---------------------------------------------------------------------------

def test_run_attack_script(make_manager, tmp_path):
    mgr = make_manager()
    mgr.container = MagicMock()
    mgr.container.exec_run.return_value = (0, b'{"success": true, "gas_used": 7}')
    res = mgr._run_attack_script(Path("reentrancy_attack.py"), {"A": "0x1"})
    assert res["success"] is True
    assert res["gas_used"] == 7
    args, kwargs = mgr.container.exec_run.call_args
    assert args[0] == ["python", "/attack_scripts/reentrancy_attack.py"]
    assert kwargs["environment"]["CONTRACT_ADDRESSES"] == json.dumps({"A": "0x1"})


# ---------------------------------------------------------------------------
# run_all / run_script
# ---------------------------------------------------------------------------

def test_run_all_deploy_failure(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    ws = tmp_path / "ws"
    ws.mkdir()
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value=None), \
         patch.object(mgr, "cleanup") as clean:
        assert mgr.run_all() == []
    clean.assert_called_once()


def test_run_all_success(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    ws = tmp_path / "ws"
    ws.mkdir()
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value={"A": "0x1"}), \
         patch.object(mgr, "_discover_attack_scripts", return_value=[Path("a_attack.py")]), \
         patch.object(mgr, "_run_attack_script", return_value={"success": True, "attack_name": "a_attack.py"}), \
         patch.object(mgr, "cleanup"):
        results = mgr.run_all()
    assert len(results) == 1
    assert results[0]["success"] is True


def test_run_script_deploy_failure(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    ws = tmp_path / "ws"
    ws.mkdir()
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value=None), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_script("reentrancy_attack.py")
    assert res["success"] is False
    assert res["logs"] == "Deployment failed"


def test_run_script_not_found(make_manager, tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    mgr = make_manager(scripts_dir=scripts)
    container = MagicMock()
    ws = tmp_path / "ws"
    ws.mkdir()
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value={"A": "0x1"}), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_script("missing_attack.py")
    assert res["success"] is False
    assert "Script not found" in res["logs"]


def test_run_script_success(make_manager, tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "reentrancy_attack.py").write_text("# attack")
    mgr = make_manager(scripts_dir=scripts)
    container = MagicMock()
    ws = tmp_path / "ws"
    ws.mkdir()
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value={"A": "0x1"}), \
         patch.object(mgr, "_run_attack_script", return_value={"success": True}), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_script("reentrancy_attack.py")
    assert res["success"] is True


# ---------------------------------------------------------------------------
# run_generated_script
# ---------------------------------------------------------------------------

def test_run_generated_script_deploy_failure(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    ws = tmp_path / "ws"
    ws.mkdir()
    script = tmp_path / "poc.py"
    script.write_text("print('x')")
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value=None), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_generated_script(script)
    assert res["success"] is False
    assert res["logs"] == "Deployment failed"


def test_run_generated_script_python(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    container.exec_run.return_value = (0, b'{"success": true}')
    ws = tmp_path / "ws"
    ws.mkdir()
    script = tmp_path / "poc.py"
    script.write_text("print('x')")
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value={"A": "0x1"}), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_generated_script(script)
    assert res["success"] is True
    args, _ = container.exec_run.call_args
    assert args[0] == ["python", "/workspace/exploit.py"]


def test_run_generated_script_javascript(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    container.exec_run.return_value = (0, b'{"success": false}')
    ws = tmp_path / "ws"
    ws.mkdir()
    script = tmp_path / "poc.js"
    script.write_text("console.log('x')")
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value={"A": "0x1"}), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_generated_script(script)
    args, _ = container.exec_run.call_args
    assert args[0] == ["node", "/workspace/exploit.js"]
    assert res["success"] is False


# ---------------------------------------------------------------------------
# _scaffold_foundry_project / run_foundry_test
# ---------------------------------------------------------------------------

def test_scaffold_foundry_project(make_manager, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Vault.sol").write_text("contract Vault {}")
    mgr = make_manager(repo=repo)
    ws = tmp_path / "ws"
    ws.mkdir()
    mgr.workspace_dir = str(ws)
    poc = tmp_path / "Poc.t.sol"
    poc.write_text("contract PocTest {}")
    mgr._scaffold_foundry_project(poc)

    toml = (ws / "foundry.toml").read_text()
    assert "remappings" in toml
    assert "/opt/forge-std" in toml
    assert (ws / "src" / "Vault.sol").exists()
    assert (ws / "test" / "Exploit.t.sol").read_text() == "contract PocTest {}"


def test_scaffold_foundry_project_copy_error_is_logged(make_manager, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Vault.sol").write_text("contract Vault {}")
    mgr = make_manager(repo=repo)
    ws = tmp_path / "ws"
    ws.mkdir()
    mgr.workspace_dir = str(ws)
    poc = tmp_path / "Poc.t.sol"
    poc.write_text("contract PocTest {}")
    # First copy (the repo .sol) raises -> warning branch; second (the PoC) succeeds.
    with patch.object(sm.shutil, "copy", side_effect=[OSError("denied"), None]):
        mgr._scaffold_foundry_project(poc)  # must not raise
    assert (ws / "foundry.toml").exists()


def test_run_foundry_test_deploy_failure(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    ws = tmp_path / "ws"
    ws.mkdir()
    poc = tmp_path / "Poc.t.sol"
    poc.write_text("contract PocTest {}")
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value=None), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_foundry_test(poc)
    assert res["success"] is False
    assert res["logs"] == "Deployment failed"


def test_run_foundry_test_passing(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    container.exec_run.return_value = (0, b"Compiler run successful!\n[PASS] testExploit()")
    ws = tmp_path / "ws"
    ws.mkdir()
    poc = tmp_path / "Poc.t.sol"
    poc.write_text("contract PocTest {}")
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value={"A": "0x1"}), \
         patch.object(mgr, "_scaffold_foundry_project"), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_foundry_test(poc)
    assert res["success"] is True
    args, kwargs = container.exec_run.call_args
    assert args[0] == ["forge", "test", "-vvv"]
    assert kwargs["workdir"] == "/workspace"


def test_run_foundry_test_failing(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    container.exec_run.return_value = (1, b"[FAIL] testExploit()")
    ws = tmp_path / "ws"
    ws.mkdir()
    poc = tmp_path / "Poc.t.sol"
    poc.write_text("contract PocTest {}")
    with patch.object(mgr, "_start_container", side_effect=_fake_start(mgr, ws, container)), \
         patch.object(mgr, "_deploy_contracts", return_value={"A": "0x1"}), \
         patch.object(mgr, "_scaffold_foundry_project"), \
         patch.object(mgr, "cleanup"):
        res = mgr.run_foundry_test(poc)
    assert res["success"] is False


# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------

def test_cleanup_stops_and_removes(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    mgr.container = container
    ws = tmp_path / "ws"
    ws.mkdir()
    mgr.workspace_dir = str(ws)
    mgr.cleanup()
    container.stop.assert_called_once()
    assert mgr.container is None
    assert mgr.workspace_dir is None
    assert not ws.exists()


def test_cleanup_stop_raises(make_manager, tmp_path):
    mgr = make_manager()
    container = MagicMock()
    container.stop.side_effect = RuntimeError("cannot stop")
    mgr.container = container
    mgr.workspace_dir = None
    mgr.cleanup()  # must not propagate
    assert mgr.container is None


def test_cleanup_noop(make_manager):
    mgr = make_manager()
    mgr.container = None
    mgr.workspace_dir = None
    mgr.cleanup()  # nothing to do, no error
    assert mgr.container is None
