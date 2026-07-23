# File: tests/ai/test_cov_ai_reasoning_agent.py
"""
Coverage tests for ReasoningAgent normalisation. The orchestrator is mocked so
no LLM is contacted. Focuses on the many model-output shapes analyse_contracts
must normalise, the line coercion helper, score_contract and general_query.
Complements tests/ai/test_reasoning_agent.py without duplicating it.
"""

import unittest
from unittest.mock import MagicMock

from hawki.core.ai_engine.llm_orchestrator import LLMOrchestrator
from hawki.core.ai_engine.reasoning_agent import ReasoningAgent


class TestAnalyseContractsShapes(unittest.TestCase):
    def setUp(self):
        self.orch = MagicMock(spec=LLMOrchestrator)
        self.agent = ReasoningAgent(orchestrator=self.orch)

    def _run(self, ret):
        self.orch.analyze.return_value = ret
        return self.agent.analyse_contracts(
            [{"name": "Test", "source": "contract Test {}", "functions": []}]
        )

    def test_bare_list_result(self):
        findings = self._run([{"title": "T", "severity": "High"}])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "T")
        self.assertEqual(findings[0]["source"], "ai")

    def test_vulnerabilities_key(self):
        findings = self._run({"vulnerabilities": [{"title": "V"}]})
        self.assertEqual(findings[0]["title"], "V")

    def test_single_bare_finding_dict(self):
        findings = self._run({"title": "Bare", "severity": "Low"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Bare")

    def test_string_finding_becomes_title(self):
        findings = self._run(["reentrancy risk"])
        self.assertEqual(findings[0]["title"], "reentrancy risk")

    def test_non_dict_non_str_item_skipped(self):
        findings = self._run([123, {"title": "Keep"}])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Keep")

    def test_alias_field_mapping(self):
        findings = self._run([{
            "vulnerability": "Alias title",
            "description": "some description",
            "consequence": "funds lost",
            "location": "MyContract.sol",
            "recommendation": "add a guard",
            "line": "L42",
        }])
        f = findings[0]
        self.assertEqual(f["title"], "Alias title")
        self.assertEqual(f["explanation"], "some description")
        self.assertEqual(f["impact"], "funds lost")
        self.assertEqual(f["file"], "MyContract.sol")
        self.assertEqual(f["fix_snippet"], "add a guard")
        self.assertEqual(f["line"], 42)

    def test_title_derived_from_explanation(self):
        findings = self._run([{"description": "First sentence here. Second."}])
        # Title taken from the first sentence of the explanation.
        self.assertEqual(findings[0]["title"], "First sentence here")

    def test_defaults_applied(self):
        findings = self._run([{"explanation": ""}])
        f = findings[0]
        self.assertEqual(f["title"], "AI-identified issue")
        self.assertEqual(f["severity"], "Medium")
        self.assertEqual(f["file"], "Test")  # falls back to contract_name
        self.assertEqual(f["line"], 0)
        self.assertEqual(f["vulnerable_snippet"], "")
        self.assertEqual(f["rule"], "AI_Reasoning")

    def test_unparseable_result_type(self):
        # A truthy non-list/non-dict result yields no findings.
        findings = self._run("just a string, not per-contract")
        self.assertEqual(findings, [])


class TestCoerceLine(unittest.TestCase):
    def test_bool_is_zero(self):
        self.assertEqual(ReasoningAgent._coerce_line(True), 0)

    def test_positive_int(self):
        self.assertEqual(ReasoningAgent._coerce_line(7), 7)

    def test_negative_int_is_zero(self):
        self.assertEqual(ReasoningAgent._coerce_line(-3), 0)

    def test_string_with_digits(self):
        self.assertEqual(ReasoningAgent._coerce_line("line 15"), 15)

    def test_string_zero_is_zero(self):
        self.assertEqual(ReasoningAgent._coerce_line("0"), 0)

    def test_no_digits_is_zero(self):
        self.assertEqual(ReasoningAgent._coerce_line("nope"), 0)

    def test_none_is_zero(self):
        self.assertEqual(ReasoningAgent._coerce_line(None), 0)


class TestScoreAndQuery(unittest.TestCase):
    def setUp(self):
        self.orch = MagicMock(spec=LLMOrchestrator)
        self.agent = ReasoningAgent(orchestrator=self.orch)

    def test_score_contract_delegates(self):
        self.orch.analyze.return_value = {"score": 42}
        out = self.agent.score_contract({"name": "C", "source": "src"})
        self.assertEqual(out, {"score": 42})
        _, kwargs = self.orch.analyze.call_args
        self.assertEqual(kwargs["template_name"], "risk_scoring_prompt")

    def test_general_query_returns_raw_response(self):
        self.orch.analyze.return_value = {"raw_response": "the answer"}
        out = self.agent.general_query("what?", {"ctx": 1})
        self.assertEqual(out, "the answer")

    def test_general_query_no_raw_response(self):
        self.orch.analyze.return_value = {"other": "x"}
        self.assertIsNone(self.agent.general_query("what?"))

    def test_general_query_none_result(self):
        self.orch.analyze.return_value = None
        self.assertIsNone(self.agent.general_query("what?"))


class TestAgentConstructsDefaultOrchestrator(unittest.TestCase):
    def test_default_orchestrator_created(self):
        # Constructing with no orchestrator builds a real LLMOrchestrator
        # (which does not itself call any LLM until analyze() runs).
        agent = ReasoningAgent()
        self.assertIsInstance(agent.orchestrator, LLMOrchestrator)


if __name__ == "__main__":
    unittest.main()
