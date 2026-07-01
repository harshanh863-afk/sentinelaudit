# Remediation Recommendations

## Priority Order

{% for finding in findings | sort(attribute='severity') %}
### {{ finding.title }}

**Severity:** {{ finding.severity }}
**Status:** {{ finding.status }}

#### Recommendation

{% if finding.detail %}
{{ finding.detail }}
{% endif %}

{% if finding.cvss_score %}
#### CVSS Score: {{ finding.cvss_score }}
{% endif %}

---
{% endfor %}
