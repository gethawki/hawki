# --------------------
# File: tests/ai/test_reasoning_agent.py
# --------------------
import unittest
from unittest.mock import MagicMock

from hawki.core.ai_engine.llm_orchestrator import LLMOrchestrator
from hawki.core.ai_engine.reasoning_agent import ReasoningAgent


class TestReasoningAgent(unittest.TestCase):
    def setUp(self):
        self.mock_orchestrator = MagicMock(spec=LLMOrchestrator)
        self.agent = ReasoningAgent(orchestrator=self.mock_orchestrator)

    def test_analyse_contracts_with_findings(self):
        # Mock orchestrator to return a finding
        self.mock_orchestrator.analyze.return_value = {
            "findings": [
                {"severity": "HIGH", "description": "test", "location": "test"}
            ]
        }
        contract_data = [{"name": "Test", "source": "contract Test {}", "functions": []}]
        findings = self.agent.analyse_contracts(contract_data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "AI_Reasoning")
        self.assertEqual(findings[0]["source"], "ai")

    def test_analyse_contracts_no_findings(self):
        self.mock_orchestrator.analyze.return_value = {"findings": []}
        contract_data = [{"name": "Test", "source": "contract Test {}", "functions": []}]
        findings = self.agent.analyse_contracts(contract_data)
        self.assertEqual(len(findings), 0)

    def test_analyse_contracts_orchestrator_fails(self):
        self.mock_orchestrator.analyze.return_value = None
        contract_data = [{"name": "Test", "source": "contract Test {}", "functions": []}]
        findings = self.agent.analyse_contracts(contract_data)
        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()