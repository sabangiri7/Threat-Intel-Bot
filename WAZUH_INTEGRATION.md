# WAZUH_INTEGRATION

**LAB-ONLY DISCLAIMER: This integration is for academic demonstration in a controlled local environment and should not be deployed to production without security review.**

## Architecture Overview

Data flow:

`Bot -> intel.log -> Wazuh Agent -> Wazuh Manager`

1. Bot generates `output/platform_snapshot.json`.
2. `scripts/generate_wazuh_logs.py` converts incidents to one-line JSON events.
3. Events are appended to `intel.log`.
4. Wazuh Agent reads JSON events and forwards them to Wazuh Manager.
5. Wazuh Manager applies local custom rules and generates alerts.

## `ossec.conf` `<localfile>` Snippet

Use forward slashes in Windows paths:

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:/WazuhLogs/intel.log</location>
</localfile>
```

## Custom Rule Group Snippet

Exact group/rules used in `wazuh_integration/local_rules.xml`:

```xml
<group name="fyp_intel,threat_intelligence,mitre,">

  <!-- Base: any intel line from this project -->
  <rule id="100100" level="10">
    <decoded_as>json</decoded_as>
    <field name="source">FYP-ThreatIntelBot</field>
    <description>FYP Threat Intel: Bot detected a threat.</description>
  </rule>

  <!-- High / critical severity (OR via pcre2 on field; if unsupported, split into two rules for CRITICAL and HIGH) -->
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <field name="severity" type="pcre2">^(CRITICAL|HIGH)$</field>
    <description>FYP Threat Intel: High/Critical severity incident detected.</description>
    <mitre>
      <id>T1071</id>
    </mitre>
  </rule>

  <!-- Emotet family -->
  <rule id="100102" level="11">
    <if_sid>100100</if_sid>
    <field name="malware_family">Emotet</field>
    <description>FYP Threat Intel: Emotet malware family detected.</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>

  <!-- BLOCK triage -->
  <rule id="100103" level="12">
    <if_sid>100100</if_sid>
    <field name="triage_action">BLOCK</field>
    <description>FYP Threat Intel: Immediate BLOCK action recommended.</description>
  </rule>

</group>
```

