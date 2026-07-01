# Executive Summary

**Target:** {{ target_url }}
**Scan Date:** {{ scan_date }}
**Risk Score:** {{ risk_score }}

## Overview

This report summarises the security assessment conducted against {{ target_url }}.
A total of {{ finding_count }} findings were identified, of which {{ critical_count }} are critical,
{{ high_count }} high, {{ medium_count }} medium, and {{ low_count }} low severity.

## Key Findings

{% for finding in critical_findings %}
- **{{ finding.title }}** ({{ finding.severity }}): {{ finding.detail }}
{% endfor %}

## Risk Summary

The overall risk score for this assessment is **{{ risk_score }}**.
