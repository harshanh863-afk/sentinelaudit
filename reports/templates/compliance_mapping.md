# Compliance Mapping

The following table maps each identified finding to relevant compliance framework controls.

{% for framework, controls in compliance_summary.items() %}
## {{ framework }}

| Control ID | Control Name | Related Findings |
|------------|--------------|------------------|
{% for control in controls %}
| {{ control.control_id }} | {{ control.control_name }} | {{ control.finding_count }} |
{% endfor %}

{% endfor %}
## Framework Coverage

| Framework | Controls Affected |
|-----------|------------------|
{% for framework, controls in compliance_summary.items() %}
| {{ framework }} | {{ controls | length }} |
{% endfor %}
