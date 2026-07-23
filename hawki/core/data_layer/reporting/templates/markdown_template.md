# Hawk-i Audit Report

**Generated:** {{ generated_at }}

## Executive Summary

- **Mode:** {{ scan_metadata.mode }} (AI: {{ scan_metadata.ai_enabled }}, Sandbox: {{ scan_metadata.sandbox_enabled }})
- **Repository:** {{ repo_data.path }} ({{ repo_data.type }})
- **Contracts Scanned:** {{ scan_metadata.total_scanned_contracts }}
- **Files Analyzed:** {{ scan_metadata.total_files }}
- **Total Findings:** {{ total_findings }}
- **Severity Breakdown:** Critical: {{ severity_counts.Critical or 0 }}, High: {{ severity_counts.High or 0 }}, Medium: {{ severity_counts.Medium or 0 }}, Low: {{ severity_counts.Low or 0 }}, Info: {{ severity_counts.Info or 0 }}
- **Simulation Success Rate:** {{ simulation_success_rate or "N/A" }}
- **Security Score:** {{ score.score }}/100 ({{ score.classification }})

{% if not scan_metadata.ai_enabled %}
> AI reasoning was not enabled during this scan.
{% endif %}
{% if not scan_metadata.sandbox_enabled %}
> Exploit simulation was not executed.
{% endif %}

## Vulnerability Breakdown

### Severity Distribution

{% if 'severity_pie.png' in chart_paths %}![Severity Pie Chart](charts/severity_pie.png){% else %}_Chart not available._{% endif %}

### Vulnerability Types (Top 10)

{% if 'type_bar.png' in chart_paths %}![Type Bar Chart](charts/type_bar.png){% else %}_Chart not available._{% endif %}

### Severity Table

| Severity | Count |
|----------|-------|
| Critical | {{ severity_counts.Critical or 0 }} |
| High     | {{ severity_counts.High or 0 }} |
| Medium   | {{ severity_counts.Medium or 0 }} |
| Low      | {{ severity_counts.Low or 0 }} |
| Info     | {{ severity_counts.Info or 0 }} |

## Detailed Findings

Each finding below shows exactly where the flaw is, the code responsible, a
plain explanation of why it is dangerous, its impact, and a concrete fix.

{% for f in findings %}
### {{ f.id }} | {{ f.severity }}: {{ f.title }}

- **Severity:** {{ f.severity }}
- **Location:** `{{ f.file }}:{{ f.line }}`
{% if f.function_name %}- **Function:** `{{ f.function_name }}`{% endif %}

**Vulnerable code**

```solidity
{{ f.vulnerable_snippet }}
```

**What is wrong**

{{ f.explanation }}

**Impact**

{{ f.impact }}

**Recommended fix**

```solidity
{{ f.fix_snippet }}
```

{% if f.exploit_steps %}
**Exploit reproduction steps**

{% for step in f.exploit_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

---
{% endfor %}

## Simulation Metrics

- **Success Rate:** {{ simulation_success_rate or "N/A" }}
- **Total Exploits Attempted:** {{ repo_data.sandbox_results | length if repo_data.sandbox_results else 0 }}

{% if repo_data.sandbox_results %}
| Attack | Success | Before | After | Gas Used | Tx Hash |
|--------|---------|--------|-------|----------|---------|
{% for res in repo_data.sandbox_results %}| {{ res.attack_name }} | {{ res.success }} | {{ res.before_balance }} | {{ res.after_balance }} | {{ res.gas_used }} | {{ res.transaction_hash }} |
{% endfor %}
{% endif %}

## Additional Security Modules

### Bytecode Verification

{% if bytecode_result %}
- **Match:** {{ bytecode_result.match }}
- **Onchain Hash:** {{ bytecode_result.onchain_hash }}
- **Compiled Hash:** {{ bytecode_result.compiled_hash }}
- **Summary:** {{ bytecode_result.diff_summary }}
{% else %}
Not performed.
{% endif %}

### Dependency Vulnerabilities

{% if dependency_findings %}
| Package | Installed | Vulnerable Versions | Severity |
|---------|-----------|---------------------|----------|
{% for dep in dependency_findings %}| {{ dep.package }} | {{ dep.installed_version }} | {{ dep.vulnerable_versions }} | {{ dep.severity }} |
{% endfor %}
{% else %}
No vulnerable dependencies found or scan not run.
{% endif %}

### Upgrade Safety

{% if upgrade_findings %}
| File | Title | Severity |
|------|-------|----------|
{% for u in upgrade_findings %}| {{ u.file }} | {{ u.title }} | {{ u.severity }} |
{% endfor %}
{% else %}
No upgrade safety issues detected.
{% endif %}

### Formal Verification

{% if formal_findings %}
| Title | Severity | Description |
|-------|----------|-------------|
{% for fv in formal_findings %}| {{ fv.title }} | {{ fv.severity }} | {{ fv.description }} |
{% endfor %}
{% else %}
No formal verification issues found or not run.
{% endif %}

### Hawk-i Deep Agent Campaign

{% if deep_agent_stats %}
- **Total attempts:** {{ deep_agent_stats.total_attempts }}
- **Successful:** {{ deep_agent_stats.successful }}
- **Rule attempts:** {{ deep_agent_stats.rule_attempts }}
- **Novel attempts:** {{ deep_agent_stats.novel_attempts }}
- **Novel successes:** {{ deep_agent_stats.novel_successes }}

{% if 'deep_outcomes.png' in chart_paths %}![Deep Agent Outcomes](charts/deep_outcomes.png){% endif %}
{% if 'deep_novel_split.png' in chart_paths %}![Novel Attack Split](charts/deep_novel_split.png){% endif %}

**Attack Timeline:**
{% for event in deep_agent_timeline %}
- {{ event.timestamp }}: {{ event.type }} attack "{{ event.name }}" success={{ event.success }}
{% endfor %}
{% else %}
Deep agent not run.
{% endif %}

---

*Report generated by Hawk-i v1.0.0*
