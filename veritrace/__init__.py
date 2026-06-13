"""Veritrace: an autonomous Tier-1 SOC analyst for Splunk that proves every step.

Veritrace investigates a Splunk alert by pivoting through Splunk over the MCP
Server, reasons with the Foundation-Sec model, records its full chain of
evidence, reasoning, confidence and actions back into Splunk as a verifiable
and replayable ledger, and ships a tuned detection-as-code rule that closes the
gap it found. Response actions are proposed for human approval.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
