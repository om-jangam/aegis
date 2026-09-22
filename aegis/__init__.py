"""Aegis - Host Firewall & Intrusion Detection System.

A production-grade host security application that combines Windows Firewall
management with live network/process monitoring, anomaly-based intrusion
detection, audit logging and real-time alerting.
"""

__version__ = "1.1.0"
__app_name__ = "Aegis"
__description__ = "Host Firewall & Intrusion Detection System"

# Internal tag applied to every firewall rule created by Aegis so the app can
# distinguish its own rules from the hundreds of default Windows rules.
RULE_TAG = "[AEGIS]"
