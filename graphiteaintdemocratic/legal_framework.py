"""
Legal framework analysis — data residency, jurisdictional authority, and
the gaps that commercial spyware exploits.

This is not a geopolitical argument. The concern is structural:
no entity — regardless of where it is based — should be permitted to
collect, process, or retain personal data about an individual without:

  1. Legitimate legal authority over that individual
  2. A lawful basis for collection under the applicable data protection regime
  3. Compliance with data residency obligations that keep the data within
     a jurisdiction where the individual has enforceable rights

Paragon Graphite fails all three when used against Americans or EU residents
outside any lawful intercept framework with proper judicial oversight.

This module documents the applicable legal frameworks, their gaps, and
what "lawful" surveillance would actually require.
"""

# ── US legal framework ────────────────────────────────────────────────────────

US_FRAMEWORKS = [
    {
        "name": "Fourth Amendment",
        "applies_to": "US government actors only",
        "what_it_guarantees": (
            "Protection against unreasonable searches and seizures by US government "
            "agents. Requires a warrant supported by probable cause, issued by a "
            "neutral magistrate, for most electronic surveillance."
        ),
        "the_gap": (
            "The Fourth Amendment does not constrain foreign governments. When Italy's "
            "intelligence service uses Paragon Graphite on an American journalist, no "
            "US constitutional protection applies — the collection is legally invisible "
            "to US law. The data can be shared with other foreign agencies under "
            "intelligence-sharing arrangements with no US judicial oversight at any point."
        ),
    },
    {
        "name": "Electronic Communications Privacy Act (ECPA, 1986)",
        "applies_to": "US government and US-based service providers",
        "what_it_guarantees": (
            "Requires US law enforcement to obtain court orders or warrants before "
            "accessing stored electronic communications or conducting real-time "
            "interception. Sets minimum standards for government access to email, "
            "cloud storage, and wire communications."
        ),
        "the_gap": (
            "ECPA governs US agencies and companies. It does not govern Israeli software "
            "companies or foreign intelligence services. A foreign government purchasing "
            "Graphite and using it against Americans is entirely outside ECPA's scope. "
            "ECPA also predates smartphones by 25 years and has significant gaps even "
            "for US law enforcement."
        ),
    },
    {
        "name": "CLOUD Act (2018)",
        "applies_to": "US companies storing data abroad",
        "what_it_guarantees": (
            "Allows US government to compel US companies (Google, Apple, Microsoft, etc.) "
            "to produce data stored outside the US. Also establishes a framework for "
            "bilateral executive agreements between the US and foreign governments for "
            "cross-border law enforcement data access."
        ),
        "the_gap": (
            "The CLOUD Act governs US-based providers. It has no mechanism to compel a "
            "foreign spyware company operating foreign servers. When Paragon's Israeli "
            "infrastructure receives exfiltrated data from an American's device, no US "
            "law can compel Paragon to preserve, disclose, or delete that data. The "
            "CLOUD Act also does not grant Americans any right to know their data was "
            "accessed or to challenge the access."
        ),
    },
    {
        "name": "No federal data residency law (United States)",
        "applies_to": "N/A — this framework does not exist",
        "what_it_guarantees": (
            "The United States has no comprehensive federal data residency requirement. "
            "Unlike the EU, which mandates that personal data on EU residents be "
            "processed under adequate legal protections before leaving the EU/EEA, the "
            "US has no equivalent framework governing where data about Americans must "
            "be stored or processed."
        ),
        "the_gap": (
            "This is the central structural gap. A US consultant spending years ensuring "
            "their clients comply with GDPR data residency rules — keeping EU personal "
            "data within the EU/EEA or in countries with adequacy decisions — has no "
            "equivalent framework to point to for protecting Americans' own data. "
            "The data exfiltrated by Graphite from an American's phone lands on Israeli "
            "servers with no US legal framework requiring it to be deleted, not shared, "
            "not retained, or made accessible to the person it belongs to."
        ),
    },
    {
        "name": "Sector-specific frameworks (HIPAA, FERPA, GLBA, CCPA)",
        "applies_to": "Health data, education records, financial data, California residents",
        "what_it_guarantees": (
            "Sector-specific protections for defined categories of sensitive data held "
            "by covered entities. HIPAA covers health information held by providers and "
            "insurers. FERPA covers education records. CCPA/CPRA gives California "
            "residents rights over their data held by businesses."
        ),
        "the_gap": (
            "These frameworks govern data custodians — the companies and institutions "
            "that hold your data as part of a service relationship. They do not govern "
            "data covertly exfiltrated by state-sponsored spyware. If Graphite copies "
            "your protected health information off your phone, HIPAA provides no remedy "
            "because the data was not obtained from a covered entity — it was stolen "
            "from your device."
        ),
    },
    {
        "name": "FISA (Foreign Intelligence Surveillance Act)",
        "applies_to": "US intelligence agencies targeting foreign powers",
        "what_it_guarantees": (
            "Establishes a secret court (FISC) that authorizes US intelligence collection "
            "targeting foreign powers and their agents. Requires court approval for "
            "electronic surveillance of Americans when foreign intelligence collection "
            "is the primary purpose."
        ),
        "the_gap": (
            "FISA governs US intelligence agencies. A foreign government's intelligence "
            "service does not need FISA authorization to surveil Americans. If a foreign "
            "service collects intelligence on Americans using Graphite and then shares "
            "it with US agencies under an intelligence-sharing agreement, the US agencies "
            "receive intelligence they could not legally collect themselves — with no "
            "FISC oversight."
        ),
    },
]

# ── EU / GDPR framework ───────────────────────────────────────────────────────

EU_FRAMEWORKS = [
    {
        "name": "GDPR — General Data Protection Regulation (EU) 2016/679",
        "applies_to": "Processing of personal data of EU/EEA residents",
        "what_it_guarantees": (
            "Comprehensive data protection rights: lawful basis for processing, purpose "
            "limitation, data minimisation, storage limitation, right of access, right "
            "to erasure, right to object, breach notification within 72 hours, and "
            "cross-border transfer restrictions requiring adequate protections."
        ),
        "data_residency_mechanism": (
            "Articles 44–49 restrict transfers of personal data to third countries. "
            "Data about EU residents can only flow to countries with an EU adequacy "
            "decision, or under Standard Contractual Clauses, Binding Corporate Rules, "
            "or other approved safeguards. Israel holds an EU adequacy decision (since "
            "2011) — but this covers commercial transfers, not intelligence collection."
        ),
        "the_gap": (
            "GDPR Article 2(2) explicitly excludes national security activities from "
            "its scope. This is the same carve-out that allows EU member states to "
            "run intelligence services. When Italy uses Paragon Graphite on Italian "
            "journalists — collecting and processing their personal data — GDPR does "
            "not apply because the activity is classified as national security. "
            "The adequacy decision for Israel covers commercial data flows; it does "
            "not mean that Israeli intelligence infrastructure handling EU residents' "
            "data meets GDPR standards."
        ),
    },
    {
        "name": "Law Enforcement Directive (EU) 2016/680",
        "applies_to": "Processing by competent authorities for law enforcement purposes",
        "what_it_guarantees": (
            "Sets data protection standards for law enforcement processing of personal "
            "data — including requirements for necessity, proportionality, and "
            "appropriate safeguards. Requires that individuals can seek judicial remedy "
            "for infringements of their rights."
        ),
        "the_gap": (
            "The LED applies to competent authorities acting within their legal mandate. "
            "It does not govern a government using commercial spyware on civil society "
            "targets outside any legitimate law enforcement investigation. Italian "
            "journalists and NGO workers targeted by Italian intelligence were not "
            "subjects of criminal investigations with judicial oversight — they were "
            "political targets. The LED's proportionality requirements were never applied."
        ),
    },
    {
        "name": "ePrivacy Directive 2002/58/EC",
        "applies_to": "Electronic communications in the EU",
        "what_it_guarantees": (
            "Prohibits interception of communications without consent, except under "
            "lawful interception regimes with appropriate safeguards. Requires "
            "confidentiality of communications and traffic data."
        ),
        "the_gap": (
            "The ePrivacy Directive requires that lawful interception follow national "
            "legal procedures. Zero-click spyware deployed without judicial authorisation "
            "violates the Directive. However, enforcement is by member states — and "
            "when the member state's own intelligence service is conducting the "
            "interception, self-enforcement is structurally improbable."
        ),
    },
]

# ── What "lawful" collection would actually require ───────────────────────────

LAWFUL_COLLECTION_REQUIREMENTS = {
    "us_resident": [
        "Judicial authorization (warrant or FISC order) from a US court with jurisdiction",
        "Probable cause or foreign intelligence necessity, documented and subject to review",
        "Minimization procedures limiting collection to the authorized target",
        "Notice to the target (or delayed notice under specific legal authority)",
        "Data retained only as long as authorized and for the stated purpose",
        "Data stored on infrastructure subject to US legal process",
        "Target's ability to challenge the collection in a competent court",
    ],
    "eu_resident": [
        "Legal basis under national law implementing the LED or ePrivacy Directive",
        "Judicial or independent administrative authorisation",
        "Proportionality assessment — necessity, subsidiarity, duration limits",
        "Data residency within EU/EEA or country with adequate protections",
        "Retention limited to investigation duration",
        "Notification to target (immediate or deferred) with right of judicial challenge",
        "Independent oversight body (e.g. IPT in UK, BfDI in Germany) with audit rights",
    ],
}

# ── The core principle ────────────────────────────────────────────────────────

CORE_PRINCIPLE = """
Data about a person should only be collected, processed, and retained by entities that:

  1. Have legitimate legal authority over that person (jurisdiction)
  2. Have a lawful basis for the specific collection (purpose, necessity, proportionality)
  3. Are subject to independent oversight with the ability to sanction violations
  4. Store the data in a jurisdiction where the person has enforceable legal rights
  5. Are required to notify the person or provide a meaningful right to challenge

This is not a statement about any country or company. It is a statement about
due process and the rule of law. Commercial spyware sold to governments and
operated through third-country infrastructure is designed specifically to
circumvent requirements 1 through 5. That is the problem.

A privacy consultant who spent decades ensuring their clients maintained GDPR
data residency compliance — keeping EU personal data within jurisdictions where
data subjects have enforceable rights — should be able to expect the same
standard applies to their own data. Currently, for Americans, no equivalent
framework exists. That gap is not an accident.
"""


def print_legal_analysis(jurisdiction: str = "us") -> None:
    frameworks = US_FRAMEWORKS if jurisdiction == "us" else EU_FRAMEWORKS
    requirements = LAWFUL_COLLECTION_REQUIREMENTS.get(
        "us_resident" if jurisdiction == "us" else "eu_resident", []
    )

    print("=" * 72)
    print(f"LEGAL FRAMEWORK ANALYSIS — {'US' if jurisdiction == 'us' else 'EU'}")
    print("=" * 72)
    print()

    for fw in frameworks:
        print(f"▸ {fw['name']}")
        print(f"  Applies to: {fw['applies_to']}")
        print(f"  Guarantees: {fw['what_it_guarantees'][:120]}...")
        print(f"  The gap:    {fw['the_gap'][:120]}...")
        print()

    print("WHAT LAWFUL COLLECTION WOULD REQUIRE:")
    for req in requirements:
        print(f"  ✓ {req}")
    print()

    print("CORE PRINCIPLE:")
    for line in CORE_PRINCIPLE.strip().splitlines():
        print(f"  {line}")
    print("=" * 72)
