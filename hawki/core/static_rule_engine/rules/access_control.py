# --------------------
# File: hawki/core/static_rule_engine/rules/access_control.py
# --------------------
"""
obsulete: this rule is too naive and generates many false positives. 
We should replace it with a more sophisticated approach that analyzes function logic and modifiers in depth.
replaced with access_control_bypass.py which looks for missing onlyOwner on sensitive functions.
Access control: checks for missing onlyOwner or similar modifiers on sensitive functions.
"""

# from . import BaseRule

# class AccessControlRule(BaseRule):
#     severity = "High"
#     explanation_template = (
#         "Sensitive functions that control critical contract state (e.g., withdraw, transferOwnership) "
#         "should be protected by an access control modifier like `onlyOwner`. Without such protection, "
#         "any user can call these functions and potentially drain funds or take over the contract."
#     )
#     impact_template = (
#         "Unauthorized users can perform privileged actions, leading to theft of funds, "
#         "contract takeover, or denial of service."
#     )
#     fix_template = (
#         "Add a modifier like `onlyOwner` to restrict access:\n"
#         "```solidity\n"
#         "modifier onlyOwner() {\n"
#         "    require(msg.sender == owner, \"Not owner\");\n"
#         "    _;\n"
#         "}\n"
#         "function {{function_name}}() {{visibility}} onlyOwner {\n"
#         "    // ...\n"
#         "}\n"
#         "```"
#     )

#     def run_check(self, contract_data):
#         findings = []
#         sensitive_names = ["withdraw", "transferOwnership", "destroy", "kill", "setOwner", "pause", "unpause"]
#         for contract in contract_data:
#             contract_name = contract.get("name", "Unknown")
#             for func in contract.get("functions", []):
#                 func_name = func.get("name", "")
#                 if any(s in func_name.lower() for s in sensitive_names):
#                     if "onlyOwner" not in func.get("modifiers", []):
#                         # Try to extract line number and snippet (simplistic)
#                         line = func.get("line", 0)
#                         snippet = f"function {func_name}(...) ..."
#                         findings.append(self._create_finding(
#                             title=f"Missing access control on {func_name}",
#                             file=contract.get("path", ""),
#                             line=line,
#                             vulnerable_snippet=snippet,
#                             function_name=func_name,
#                             visibility=func.get("visibility", "public"),
#                         ))
#         return findings
# # EOF: hawki/core/static_rule_engine/rules/access_control.py
