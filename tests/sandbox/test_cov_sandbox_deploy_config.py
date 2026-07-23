# File: tests/sandbox/test_cov_sandbox_deploy_config.py
"""Coverage tests for deploy.py and docker_config.py.

Everything external (web3, solcx, docker) is mocked; no chain, compiler, or
docker daemon is ever contacted.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from hawki.core.exploit_sandbox import deploy as dep
from hawki.core.exploit_sandbox import docker_config as dc
from hawki.core.exploit_sandbox.docker_config import DockerConfig

# ---------------------------------------------------------------------------
# deploy.main
# ---------------------------------------------------------------------------

def _connected_w3():
    w3 = MagicMock()
    w3.is_connected.return_value = True
    w3.eth.accounts = ["0xDEPLOYER"]
    receipt = MagicMock()
    receipt.contractAddress = "0xCONTRACT"
    w3.eth.wait_for_transaction_receipt.return_value = receipt
    return w3


def test_deploy_not_connected():
    w3 = MagicMock()
    w3.is_connected.return_value = False
    with patch.object(dep, "Web3") as MW:
        MW.return_value = w3
        with pytest.raises(SystemExit):
            dep.main()


def test_deploy_install_solc_failure():
    w3 = _connected_w3()
    with patch.object(dep, "Web3") as MW, \
         patch.object(dep, "install_solc", side_effect=RuntimeError("no net")), \
         patch.object(dep, "set_solc_version"):
        MW.return_value = w3
        with pytest.raises(SystemExit):
            dep.main()


def test_deploy_no_sol_files():
    w3 = _connected_w3()
    with patch.object(dep, "Web3") as MW, \
         patch.object(dep, "install_solc"), \
         patch.object(dep, "set_solc_version"), \
         patch.object(dep.glob, "glob", return_value=[]):
        MW.return_value = w3
        with pytest.raises(SystemExit):
            dep.main()


def test_deploy_happy_path(tmp_path):
    """Exercises the deployable / no-bin / ctor-args / deploy-failure branches."""
    w3 = _connected_w3()
    Contract = MagicMock()
    # First deployable contract succeeds, second raises during transact.
    Contract.constructor.return_value.transact.side_effect = [
        b"txhash", RuntimeError("revert"),
    ]
    w3.eth.contract.return_value = Contract

    compiled = {
        "/repo/Foo.sol:Foo": {"bin": "60ff", "abi": [{"type": "function"}]},
        "/repo/Foo.sol:IFace": {"bin": "", "abi": []},
        "/repo/Foo.sol:NeedsArgs": {
            "bin": "60aa",
            "abi": [{"type": "constructor", "inputs": [{"name": "x", "type": "uint256"}]}],
        },
        "/repo/Foo.sol:Boom": {"bin": "60bb", "abi": []},
    }
    with patch.object(dep, "Web3") as MW, \
         patch.object(dep, "install_solc"), \
         patch.object(dep, "set_solc_version"), \
         patch.object(dep.glob, "glob", return_value=["/repo/Foo.sol"]), \
         patch.object(dep, "compile_files", return_value=compiled), \
         patch.object(dep, "Path", return_value=tmp_path):
        MW.return_value = w3
        dep.main()

    data = json.loads((tmp_path / "addresses.json").read_text())
    # Only Foo deploys: IFace has no bytecode, NeedsArgs has ctor args, Boom reverts.
    assert data == {"Foo": "0xCONTRACT"}


# ---------------------------------------------------------------------------
# DockerConfig
# ---------------------------------------------------------------------------

def test_ensure_image_found():
    client = MagicMock()
    with patch.object(dc.docker, "from_env", return_value=client), \
         patch.object(DockerConfig, "_build_image") as build:
        cfg = DockerConfig()
    client.images.get.assert_called_once_with(cfg.IMAGE_NAME)
    build.assert_not_called()


def test_ensure_image_not_found_triggers_build():
    client = MagicMock()
    client.images.get.side_effect = dc.docker.errors.ImageNotFound("nope")
    with patch.object(dc.docker, "from_env", return_value=client), \
         patch.object(DockerConfig, "_build_image") as build:
        DockerConfig()
    build.assert_called_once()


def test_ensure_image_docker_exception_reraised():
    client = MagicMock()
    client.images.get.side_effect = dc.DockerException("daemon down")
    with patch.object(dc.docker, "from_env", return_value=client):
        with pytest.raises(dc.DockerException):
            DockerConfig()


def _bare_config(client):
    """Construct a DockerConfig whose __init__ side effects are neutralised."""
    with patch.object(dc.docker, "from_env", return_value=client), \
         patch.object(DockerConfig, "_ensure_image"):
        cfg = DockerConfig()
    cfg.client = client
    return cfg


def test_build_image_success():
    client = MagicMock()
    client.images.build.return_value = (
        MagicMock(),
        [{"stream": "Step 1/2\n"}, {"aux": {"ID": "sha256:x"}}],
    )
    cfg = _bare_config(client)
    cfg._build_image()  # should not raise
    client.images.build.assert_called_once()


def test_build_image_build_error_reraised():
    client = MagicMock()
    client.images.build.side_effect = dc.BuildError("bad dockerfile", build_log=[])
    cfg = _bare_config(client)
    with pytest.raises(dc.BuildError):
        cfg._build_image()


def test_build_image_generic_error_reraised():
    client = MagicMock()
    client.images.build.side_effect = ValueError("boom")
    cfg = _bare_config(client)
    with pytest.raises(ValueError):
        cfg._build_image()
