# Findings

{% for finding in findings %}
## {{ loop.index }}. {{ finding.title }}

| Field | Value |
|-------|-------|
| Severity | {{ finding.severity }} |
| Status | {{ finding.status }} |
| CVSS | {{ finding.cvss_score or 'N/A' }} |
| Category | {{ finding.finding_type or 'N/A' }} |

### Description

{{ finding.detail }}

### Compliance Mapping

{% for cm in finding.compliance %}
- **{{ cm.framework }}:** {{ cm.control_id }} — {{ cm.control_name }}
{% endfor %}

{% if finding.evidence_summary %}
### Evidence

```
{{ finding.evidence_summary }}
```
{% endif %}

---
{% endfor %}
