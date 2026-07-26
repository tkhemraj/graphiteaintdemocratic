"""
PII exposure mapping — where does your data go when Graphite compromises your device?

Paragon's architecture exfiltrates device data through a chain:
  Device → Victim-facing C2 (VPS) → Paragon Israeli core infra → Customer operator

American citizens' private data (messages, location, contacts, photos) flows through
servers in multiple jurisdictions with minimal legal oversight or transparency.

This module documents that chain and flags which known infrastructure
was involved in any given compromise.

Sources:
  Citizen Lab March + June 2025
  WhatsApp Inc. v. Paragon Solutions Ltd., NDCA 2025
  Privacy International: "Who Watches the Watchers" 2024
"""

from dataclasses import dataclass, field


@dataclass
class DataFlowNode:
    label: str
    location: str
    operator: str
    ip: str
    legal_jurisdiction: str
    notes: str


@dataclass
class PiiExposureReport:
    target_name: str = ""
    target_country: str = ""
    attack_vector: str = ""
    data_categories_at_risk: list[str] = field(default_factory=list)
    exfiltration_chain: list[DataFlowNode] = field(default_factory=list)
    customer_codename: str = ""
    customer_attributed_country: str = ""
    legal_exposure_notes: list[str] = field(default_factory=list)


# The known Paragon data exfiltration chain for the Italy/EU cluster
GRAPHITE_DATA_FLOW = [
    DataFlowNode(
        label="Victim Device",
        location="Target country (e.g. Italy, USA)",
        operator="Target (unwitting)",
        ip="",
        legal_jurisdiction="Varies",
        notes="Device fully compromised; all app data readable in memory after sandbox escape",
    ),
    DataFlowNode(
        label="Victim-facing C2",
        location="Austria (EDIS Global VPS)",
        operator="Paragon / Customer",
        ip="46.183.184.91",
        legal_jurisdiction="Austria / EU GDPR nominally applies",
        notes="First hop; strips identifying metadata before forwarding to core infra",
    ),
    DataFlowNode(
        label="Paragon Core Infrastructure",
        location="Israel",
        operator="Paragon Solutions Ltd.",
        ip="84.110.122.27 / 178.237.39.204 / 84.110.47.82-86",
        legal_jurisdiction="Israel — not EU, not USA",
        notes=(
            "All customer data passes through Paragon's own servers. "
            "Paragon claims they cannot see customer content, but their infrastructure "
            "sits in the middle of every exfiltration chain. No independent audit exists."
        ),
    ),
    DataFlowNode(
        label="Customer Operator",
        location="Customer country (Italy, Canada, Singapore, etc.)",
        operator="Government agency (e.g. Italian intelligence, Ontario Provincial Police)",
        ip="Operator-codename domains",
        legal_jurisdiction="Customer country law",
        notes=(
            "End recipient of compromised data. In Italy's case, Fanpage.it reporting "
            "confirmed data on journalists was shared with political figures."
        ),
    ),
]

# Categories of data Graphite exfiltrates (from Citizen Lab forensics + WhatsApp lawsuit)
PII_CATEGORIES = [
    "End-to-end encrypted messages (Signal, WhatsApp, iMessage) — read in plaintext after decryption in memory",
    "Real-time GPS location and location history",
    "Contacts (name, phone, email, relationship metadata)",
    "Call logs (inbound/outbound, duration, timestamps)",
    "Emails and drafts",
    "Photos and videos (including deleted, recovered from app caches)",
    "Calendar events and meeting attendees",
    "Browsing history and bookmarks",
    "Microphone audio (ambient recording capability)",
    "Camera (photo/video capture without user knowledge)",
    "Keystrokes and clipboard content",
    "Wi-Fi networks and connection history (reveals physical locations)",
    "Device identifiers (IMEI, UDID, advertising ID)",
    "App usage patterns and screen content",
]

AMERICAN_PII_LEGAL_NOTES = [
    (
        "No FISA warrant required: Foreign governments purchasing Graphite can target "
        "Americans abroad or Americans communicating with foreign nationals without any "
        "US court authorization."
    ),
    (
        "Fourth Amendment gap: Paragon sells to foreign state actors. When Italy's "
        "government uses Graphite on an Italian-American journalist, no US legal "
        "process is required — the data simply flows to Rome."
    ),
    (
        "CLOUD Act does not apply: The CLOUD Act governs US companies storing data "
        "abroad. Paragon is Israeli. Their servers are Israeli. No US data-protection "
        "law directly constrains what they collect or retain."
    ),
    (
        "No breach notification: There is no law requiring Paragon or their customers "
        "to notify American targets that their devices were compromised."
    ),
    (
        "Data retention unknown: Paragon's retention policies for exfiltrated data "
        "are not public. Citizen Lab found no evidence they are audited."
    ),
]

KNOWN_AMERICAN_TARGETS = [
    {
        "name": "Multiple US-based journalists",
        "context": "Received Apple threat notifications Jan 2025 alongside Italian targets",
        "source": "Apple threat notification + Citizen Lab June 2025",
        "confirmed": False,  # Apple notifications confirmed, Graphite attribution pending
    },
]


def generate_exposure_report(
    target_name: str = "Unknown",
    target_country: str = "Unknown",
    customer_codename: str = "",
) -> PiiExposureReport:
    customer_country = _codename_to_country(customer_codename)
    return PiiExposureReport(
        target_name=target_name,
        target_country=target_country,
        attack_vector="Graphite spyware (Paragon Solutions)",
        data_categories_at_risk=PII_CATEGORIES,
        exfiltration_chain=GRAPHITE_DATA_FLOW,
        customer_codename=customer_codename,
        customer_attributed_country=customer_country,
        legal_exposure_notes=AMERICAN_PII_LEGAL_NOTES,
    )


def _codename_to_country(codename: str) -> str:
    mapping = {
        "astra": "Australia",
        "abba": "Australia",
        "cap": "Canada (Ontario Provincial Police)",
        "drt": "Denmark",
        "muki": "Israel",
        "cag": "Cyprus",
        "sht": "Singapore",
    }
    return mapping.get(codename.lower(), "Unknown")


def print_exposure_report(report: PiiExposureReport) -> None:
    print("=" * 70)
    print("GRAPHITE PII EXPOSURE REPORT")
    print("=" * 70)
    if report.target_name and report.target_name != "Unknown":
        print(f"Target:          {report.target_name} ({report.target_country})")
    if report.customer_codename:
        print(f"Operator:        {report.customer_codename} — {report.customer_attributed_country}")
    print()

    print("DATA EXFILTRATION CHAIN:")
    for i, node in enumerate(report.exfiltration_chain):
        arrow = "↓" if i < len(report.exfiltration_chain) - 1 else ""
        print(f"  [{i+1}] {node.label}")
        print(f"      Location:     {node.location}")
        print(f"      Jurisdiction: {node.legal_jurisdiction}")
        if node.ip:
            print(f"      IP/domain:    {node.ip}")
        print(f"      Note: {node.notes[:100]}")
        if arrow:
            print(f"       {arrow}")
    print()

    print(f"DATA CATEGORIES AT RISK ({len(report.data_categories_at_risk)}):")
    for cat in report.data_categories_at_risk:
        print(f"  • {cat}")
    print()

    print("US LEGAL EXPOSURE:")
    for note in report.legal_exposure_notes:
        print(f"  ! {note[:120]}")
    print("=" * 70)
