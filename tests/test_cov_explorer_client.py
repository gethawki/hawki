# File: tests/test_cov_explorer_client.py
"""
Coverage for core.explorer.client.ExplorerClient: constructor validation and
get_contract_source response parsing. All HTTP is mocked (no network).
"""

import unittest
from unittest import mock

from hawki.core.explorer import client as explorer_client
from hawki.core.explorer.client import ExplorerClient


def _resp(json_data, raise_exc=None):
    r = mock.MagicMock()
    if raise_exc is not None:
        r.raise_for_status.side_effect = raise_exc
    else:
        r.raise_for_status.return_value = None
    r.json.return_value = json_data
    return r


class TestConstructor(unittest.TestCase):
    def test_valid_chain_builds_url(self):
        c = ExplorerClient("ethereum", api_key="KEY")
        self.assertEqual(c.api_url, "https://api.etherscan.io/api")
        self.assertEqual(c.api_key, "KEY")
        self.assertEqual(c.chain, "ethereum")

    def test_default_api_key_empty(self):
        self.assertEqual(ExplorerClient("polygon").api_key, "")

    def test_chain_without_explorer_raises(self):
        with self.assertRaises(ValueError):
            ExplorerClient("local")

    def test_unknown_chain_raises(self):
        with self.assertRaises(ValueError):
            ExplorerClient("not-a-chain")


class TestGetContractSource(unittest.TestCase):
    def setUp(self):
        self.client = ExplorerClient("ethereum", api_key="KEY")

    def test_success_returns_contract_data(self):
        data = {"status": "1", "message": "OK", "result": [
            {"SourceCode": "contract A {}", "ContractName": "A"}
        ]}
        with mock.patch.object(explorer_client.requests, "get", return_value=_resp(data)) as g:
            out = self.client.get_contract_source("0xabc")
        self.assertEqual(out["ContractName"], "A")
        # URL + params passed correctly.
        args, kwargs = g.call_args
        self.assertEqual(args[0], "https://api.etherscan.io/api")
        self.assertEqual(kwargs["params"]["address"], "0xabc")
        self.assertEqual(kwargs["params"]["action"], "getsourcecode")
        self.assertEqual(kwargs["params"]["apikey"], "KEY")

    def test_status_not_ok_returns_none(self):
        data = {"status": "0", "message": "NOTOK", "result": []}
        with mock.patch.object(explorer_client.requests, "get", return_value=_resp(data)):
            self.assertIsNone(self.client.get_contract_source("0xabc"))

    def test_empty_result_returns_none(self):
        data = {"status": "1", "result": []}
        with mock.patch.object(explorer_client.requests, "get", return_value=_resp(data)):
            self.assertIsNone(self.client.get_contract_source("0xabc"))

    def test_unverified_empty_sourcecode_returns_none(self):
        data = {"status": "1", "result": [{"SourceCode": "", "ContractName": ""}]}
        with mock.patch.object(explorer_client.requests, "get", return_value=_resp(data)):
            self.assertIsNone(self.client.get_contract_source("0xabc"))

    def test_http_error_returns_none(self):
        with mock.patch.object(
            explorer_client.requests, "get",
            return_value=_resp({}, raise_exc=RuntimeError("500")),
        ):
            self.assertIsNone(self.client.get_contract_source("0xabc"))


if __name__ == "__main__":
    unittest.main()
