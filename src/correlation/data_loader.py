"""
Data Loader for Week 6 Correlation Engine
Creates folder structure and generates enriched IOCs dataset.
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
import random


def setup_folder_structure():
    """Create all necessary folders for Week 6."""
    print("📁 Creating folder structure...")
    folders = [
        "data/correlation",
        "src/correlation",
        "src/correlation/rules",
        "src/correlation/engine",
        "tests/correlation"
    ]

    for folder in folders:
        Path(folder).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {folder}")

    # Create __init__.py files
    print("\n📝 Creating __init__.py files...")
    init_files = [
        "src/correlation/__init__.py",
        "src/correlation/rules/__init__.py",
        "src/correlation/engine/__init__.py",
        "tests/correlation/__init__.py"
    ]

    for init_file in init_files:
        Path(init_file).touch()
        print(f"  ✓ {init_file}")


def generate_enriched_iocs(count: int = 60) -> list:
    """Generate synthetic enriched IOCs with realistic data."""
    print(f"\n🔍 Generating {count} enriched IOCs...")
    enriched_iocs = []
    now = datetime.utcnow()

    # IOC values to generate
    domains = [f"malware-c2-{i}.com" for i in range(15)]
    ips = [f"192.168.{i//256}.{i%256}" for i in range(15)]
    urls = [f"https://malware-{i}.ru/payload" for i in range(15)]
    hashes = [f"{'a'*i}{'b'*(64-i)}" for i in range(15)]

    all_values = domains + ips + urls + hashes

    for idx, val in enumerate(all_values[:count]):
        # Determine type
        if val.startswith("https://"):
            ioc_type = "URL"
        elif val[:3].isdigit():
            ioc_type = "IP"
        elif len(val) == 64 and all(c in '0123456789abcdef' for c in val):
            ioc_type = "HASH"
        else:
            ioc_type = "DOMAIN"

        # Create enriched IOC
        enriched = {
            "ioc_value": val,
            "ioc_type": ioc_type,
            "unified_confidence": round(random.uniform(0.60, 0.99), 2),
            "triage_action": random.choice(["BLOCK", "MONITOR", "IGNORE"]),
            "timestamp": (now - timedelta(days=random.randint(0, 30))).isoformat() + "Z",
            "malware_family": random.choice(["Trojan.A", "Ransom.X", "Infostealer.Z", "Botnet.Y", "Worm.M"]),
            "resolves_to": [random.choice(ips)] if ioc_type == "DOMAIN" else [],
            "otx_pulses": [f"pulse-{random.randint(1, 10):03d}"] if random.random() > 0.5 else [],
            "api_results": {
                "virustotal": {
                    "verdict": "malicious",
                    "detections": random.randint(15, 70),
                    "scan_date": now.isoformat() + "Z"
                },
                "abuseipdb": {
                    "abuse_confidence_score": random.randint(20, 100),
                    "total_reports": random.randint(5, 500)
                },
                "otx": {
                    "reputation": random.randint(-100, -20),
                    "indicator_count": random.randint(1, 20)
                },
                "threatfox": {
                    "threat_type": random.choice(["Trojan", "Malware", "PUA", "Ransomware"])
                }
            }
        }
        enriched_iocs.append(enriched)

    return enriched_iocs


def save_enriched_iocs(iocs: list, output_path: str = "data/enriched_iocs.json"):
    """Save enriched IOCs to JSON file."""
    print(f"\n💾 Saving {len(iocs)} IOCs...")
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(iocs, indent=2))
    print(f"  ✅ Saved to: {output}")
    print(f"  📊 File size: {output.stat().st_size / 1024:.1f} KB")


def print_summary(iocs: list):
    """Print summary of generated IOCs."""
    print("\n📈 IOC Type Breakdown:")
    types = {}
    for ioc in iocs:
        t = ioc["ioc_type"]
        types[t] = types.get(t, 0) + 1

    for t, count in sorted(types.items()):
        print(f"  • {t}: {count}")

    print("\n" + "="*70)
    print("✅ WEEK 6 SETUP COMPLETE!")
    print("="*70)
    print(f"\n📊 Summary:")
    print(f"  • Folders created: 5")
    print(f"  • Init files created: 4")
    print(f"  • IOCs generated: {len(iocs)}")
    print("\n📁 Ready for Monday checklist:")
    print("  1. Verify data:")
    print("     python -c \"import json; d=json.load(open('data/enriched_iocs.json')); print(f'Total IOCs: {len(d)}')\"")
    print("\n  2. Git commit:")
    print("     git add . && git commit -m 'Week 6: Setup folders + generate IOCs'")
    print("\n  3. Push:")
    print("     git push origin main")
    print("="*70 + "\n")


def main():
    """Main execution."""
    print("\n" + "="*70)
    print("🚀 WEEK 6 DATA LOADER")
    print("="*70)

    # Step 1: Create folder structure
    setup_folder_structure()

    # Step 2: Generate IOCs
    iocs = generate_enriched_iocs(count=60)

    # Step 3: Save IOCs
    save_enriched_iocs(iocs)

    # Step 4: Print summary
    print_summary(iocs)


if __name__ == "__main__":
    main()