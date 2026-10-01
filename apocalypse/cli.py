import argparse
import json
import os
from pathlib import Path

from .ai import DEFAULT_GROQ_MODEL
from .config import Settings
from .engine import run_security_scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Project Apocalypse AI Security Intelligence PoC")
    parser.add_argument("--fixture", type=Path, help="Analyze local JSON records without contacting Microsoft")
    parser.add_argument("--json", action="store_true", help="Emit clean, machine-readable JSON output (ideal for API/UI)")
    parser.add_argument("--raw-groq", action="store_true", help="Print the exact raw JSON string returned directly from Groq")
    parser.add_argument("--heuristic-only", action="store_true", help="Skip AI reasoning and use heuristic analyzer only")
    parser.add_argument("--model", type=str, default=None, help=f"Groq model name (default: {DEFAULT_GROQ_MODEL})")
    args = parser.parse_args()

    settings = Settings()

    # Progress logger for console (suppressed when pure JSON output requested)
    def cli_progress(msg: str) -> None:
        if not args.json and not args.raw_groq:
            print(msg, flush=True)

    try:
        result = run_security_scan(
            progress=cli_progress,
            fixture_path=args.fixture,
            heuristic_only=args.heuristic_only,
            model=args.model,
            settings=settings,
        )
    except Exception as error:
        parser.error(str(error))

    if args.raw_groq or args.json:
        print(json.dumps(result, indent=2))
        return

    # Formatted terminal display
    print("\n" + "=" * 70)
    print("  PROJECT APOCALYPSE — SECURITY INTELLIGENCE AGENT")
    print("=" * 70)
    print(f"Signals Analyzed : {result.get('records_analyzed', 0)}")
    print(f"Analysis Engine  : {result.get('engine', 'Unknown')}")

    score = result.get("enterprise_security_score")
    threat_level = result.get("overall_threat_level")
    if score is not None:
        print(f"Security Score   : {score}/100")
        print(f"Overall Threat   : {threat_level}")
        print("-" * 70)
        print(f"Executive Summary:\n{result.get('executive_summary', '')}")
        print("=" * 70)
        print("\nIDENTIFIED THREATS & ATTACK CHAINS:")
        for idx, threat in enumerate(result.get("perceived_threats", []), start=1):
            sev = threat.get("severity", "UNKNOWN").upper()
            title = threat.get("title", "Unknown Threat")
            conf = threat.get("confidence", 0.0)
            entities = ", ".join(threat.get("affected_entities", [])) or "None specified"
            narrative = threat.get("attack_chain_narrative", "")
            blast = threat.get("predicted_blast_radius", "")
            recs = threat.get("recommendations", {})

            print(f"\n{idx}. [{sev}] {title} (Confidence: {int(conf * 100)}%)")
            if entities:
                print(f"   Target Entities  : {entities}")
            if narrative:
                print(f"   Attack Narrative : {narrative}")
            if blast:
                print(f"   Blast Radius     : {blast}")
            if recs.get("immediate_action"):
                print(f"   Immediate Action : {recs['immediate_action']}")
            if recs.get("recommended_microsoft_controls"):
                print(f"   Microsoft Controls: {', '.join(recs['recommended_microsoft_controls'])}")
    else:
        findings = result.get("findings", [])
        print(f"Total Findings   : {len(findings)}")
        print("-" * 70)
        for index, finding in enumerate(findings, start=1):
            print(f"\n{index}. [{finding.get('severity', '').upper()}] {finding.get('title', '')} ({finding.get('source', '')})")
            for evidence in finding.get("evidence", []):
                print(f"   Evidence       : {evidence}")
            print(f"   Recommendation : {finding.get('recommendation', '')}")

    if os.getenv("APOCALYPSE_WRITE_ENABLED"):
        print("\nWARNING: APOCALYPSE_WRITE_ENABLED is ignored; this PoC has no write code.")

