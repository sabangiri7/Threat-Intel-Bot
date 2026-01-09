#!/usr/bin/env python3
"""
CLI Demo Script - Threat Intelligence Bot Phase 3.1
End-to-end demonstration of correlation engine
"""

import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DemoDataGenerator:
    """Generate realistic sample enriched IOCs for demo."""
    
    @staticmethod
    def generate_sample_iocs(count: int = 20) -> List[Dict]:
        """
        Generate sample enriched IOCs.
        
        Args:
            count: Number of IOCs to generate
            
        Returns:
            List of enriched IOC dictionaries
        """
        logger.info(f"Generating {count} sample IOCs")
        
        base_time = datetime(2026, 1, 7, 12, 0, 0)
        iocs = []
        
        # Trojan.A infrastructure (Rule 1)
        shared_ip = "192.168.1.10"
        for i in range(5):
            ioc = {
                'iocvalue': f'malware-c2-{i}.com',
                'ioctype': 'DOMAIN',
                'unifiedconfidence': 0.85 + (i * 0.02),
                'triageaction': 'BLOCK',
                'timestamp': (base_time + timedelta(hours=i)).isoformat() + 'Z',
                'malwarefamily': 'Trojan.A',
                'resolvesto': shared_ip,
                'otxpulses': ['pulse-001', 'pulse-002'],
                'apiresults': {
                    'virustotal': {'malicious': 45 + i, 'detections': 45 + i},
                    'otx': {'pulsecount': 3},
                    'threatfox': {'confidencelevel': 95},
                    'abuseipdb': {'abuseconfidencescore': 80}
                }
            }
            iocs.append(ioc)
        
        # Trojan.A infrastructure - related IPs (Rule 1)
        for i in range(3):
            ioc = {
                'iocvalue': f'192.168.1.{10 + i}',
                'ioctype': 'IP',
                'unifiedconfidence': 0.82 + (i * 0.03),
                'triageaction': 'BLOCK',
                'timestamp': (base_time + timedelta(hours=8 + i)).isoformat() + 'Z',
                'malwarefamily': 'Trojan.A',
                'resolvesto': '',
                'otxpulses': ['pulse-001'],
                'apiresults': {
                    'virustotal': {'malicious': 50},
                    'otx': {'pulsecount': 2},
                    'threatfox': {'confidencelevel': 92},
                    'abuseipdb': {'abuseconfidencescore': 85}
                }
            }
            iocs.append(ioc)
        
        # Ransom.X family (Rule 2)
        for i in range(4):
            ioc = {
                'iocvalue': f'ransomware-payload-{i}.ru',
                'ioctype': 'URL',
                'unifiedconfidence': 0.70 + (i * 0.05),
                'triageaction': 'BLOCK',
                'timestamp': (base_time + timedelta(days=i)).isoformat() + 'Z',
                'malwarefamily': 'Ransom.X',
                'resolvesto': f'192.168.2.{50 + i}',
                'otxpulses': ['pulse-003'],
                'apiresults': {
                    'virustotal': {'malicious': 55},
                    'otx': {'pulsecount': 4},
                    'threatfox': {'confidencelevel': 88},
                    'abuseipdb': {'abuseconfidencescore': 75}
                }
            }
            iocs.append(ioc)
        
        # Ransom.X hashes
        hash_values = ['d41d8cd98f00b204e9800998ecf8427e',
                       'e99a18c428cb38d5f260853678922e03',
                       '5d41402abc4b2a76b9719d911017c592']
        for i, hash_val in enumerate(hash_values):
            ioc = {
                'iocvalue': hash_val,
                'ioctype': 'HASH',
                'unifiedconfidence': 0.75 + (i * 0.05),
                'triageaction': 'BLOCK',
                'timestamp': (base_time + timedelta(days=i)).isoformat() + 'Z',
                'malwarefamily': 'Ransom.X',
                'resolvesto': '',
                'otxpulses': [],
                'apiresults': {
                    'virustotal': {'malicious': 60},
                    'otx': {'pulsecount': 5},
                    'threatfox': {'confidencelevel': 90},
                    'abuseipdb': {'abuseconfidencescore': 0}
                }
            }
            iocs.append(ioc)
        
        # Clean IOCs (low severity)
        clean_iocs = [
            ('8.8.8.8', 'IP', 0.05),
            ('google.com', 'DOMAIN', 0.10),
            ('cloudflare.com', 'DOMAIN', 0.08),
        ]
        for ioc_value, ioc_type, confidence in clean_iocs:
            ioc = {
                'iocvalue': ioc_value,
                'ioctype': ioc_type,
                'unifiedconfidence': confidence,
                'triageaction': 'IGNORE',
                'timestamp': (base_time + timedelta(days=2)).isoformat() + 'Z',
                'malwarefamily': 'UNKNOWN',
                'resolvesto': '',
                'otxpulses': [],
                'apiresults': {}
            }
            iocs.append(ioc)
        
        logger.info(f"Generated {len(iocs)} sample IOCs")
        return iocs[:count]


class CorrelationDemo:
    """Demo runner for correlation engine."""
    
    def __init__(self, verbose: bool = False):
        """Initialize demo."""
        self.verbose = verbose
        self.engine = None
        self._import_engine()
    
    def _import_engine(self):
        """Import correlation engine."""
        try:
            from src.correlation.engine.engine import correlate_iocs
            logger.info("Imported correlation engine from src.correlation.engine")
        except ImportError:
            try:
                from correlation.engine import correlate_iocs
                logger.info("Imported correlation engine from correlation.engine")
            except ImportError:
                logger.error("Could not import correlation engine")
                sys.exit(1)
        
        self.correlate_iocs = correlate_iocs
    
    def run_demo(self, num_iocs: int = 20, output_file: str = None):
        """
        Run complete demo.
        
        Args:
            num_iocs: Number of sample IOCs to generate
            output_file: Optional file to save results
        """
        print("\n" + "="*80)
        print("🔍 THREAT INTELLIGENCE BOT - CORRELATION ENGINE DEMO")
        print("="*80)
        print(f"Phase 3.1 - Week 6 (January 7-13, 2026)")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        # Step 1: Generate sample data
        print("📊 STEP 1: Generate Sample IOCs")
        print("-" * 80)
        generator = DemoDataGenerator()
        iocs = generator.generate_sample_iocs(num_iocs)
        
        ioc_types = {}
        for ioc in iocs:
            ioc_type = ioc['ioctype']
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
        
        print(f"✓ Generated {len(iocs)} IOCs\n")
        print("  IOC Type Breakdown:")
        for ioc_type, count in sorted(ioc_types.items()):
            print(f"    - {ioc_type}: {count}")
        print()
        
        # Step 2: Run correlation
        print("\n📈 STEP 2: Run Correlation Engine")
        print("-" * 80)
        try:
            incidents = self.correlate_iocs(iocs)
        except Exception as e:
            logger.error(f"Correlation failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
        
        print(f"✓ Generated {len(incidents)} incident groups\n")
        
        # Step 3: Display results
        print("\n🎯 STEP 3: Incident Groups")
        print("-" * 80)
        
        for incident in incidents:
            self._print_incident(incident)
        
        # Step 4: Summary statistics
        print("\n📊 STEP 4: Summary Statistics")
        print("-" * 80)
        self._print_summary(iocs, incidents)
        
        # Step 5: Save results if requested
        if output_file:
            self._save_results(incidents, output_file)
        
        print("\n" + "="*80)
        print("✅ DEMO COMPLETE")
        print("="*80 + "\n")
    
    @staticmethod
    def _print_incident(incident: Dict):
        """Print single incident details."""
        inc_id = incident['incident_id']
        score = incident['score']
        group_size = incident['group_size']
        severity = score.get('severity_level', 'UNKNOWN')
        final_score = score.get('final_score', 0.0)
        families = ', '.join(incident['malware_families'])
        
        print(f"\n  {inc_id} | Severity: {severity:8} | Score: {final_score:6.1f}")
        print(f"  {'─' * 76}")
        print(f"  IOCs in group:     {group_size}")
        print(f"  Malware families:  {families}")
        print(f"  IOC types:         {', '.join(incident['ioc_types'])}")
        print(f"  Score breakdown:")
        print(f"    - Base score:      {score.get('base_score', 0):.1f}")
        print(f"    - Confidence:      +{score.get('confidence_boost', 0):.1f}")
        print(f"    - Sources:         +{score.get('source_boost', 0):.1f}")
        print(f"    - Size bonus:      +{score.get('size_bonus', 0):.1f}")
        print(f"    - Action mult:     {score.get('action_multiplier', 1.0):.2f}x")
        print(f"  Reasoning: {score.get('reasoning', '')}")
        print(f"  IOCs: {', '.join(incident['ioc_values'][:3])}", end='')
        if len(incident['ioc_values']) > 3:
            print(f" + {len(incident['ioc_values']) - 3} more")
        else:
            print()
    
    @staticmethod
    def _print_summary(iocs: List[Dict], incidents: List[Dict]):
        """Print summary statistics."""
        print(f"Total IOCs processed:        {len(iocs)}")
        print(f"Incident groups generated:   {len(incidents)}")
        
        if incidents:
            avg_group_size = sum(i['group_size'] for i in incidents) / len(incidents)
            print(f"Average group size:          {avg_group_size:.1f}")
            
            severity_counts = {}
            for incident in incidents:
                sev = incident['score'].get('severity_level', 'UNKNOWN')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            print(f"\n  Severity breakdown:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    print(f"    - {severity:8}: {count:2} incidents")
            
            families = set()
            for incident in incidents:
                families.update(incident['malware_families'])
            
            print(f"\n  Unique malware families:    {len(families)}")
            for family in sorted(families):
                if family != 'UNKNOWN':
                    print(f"    - {family}")
    
    @staticmethod
    def _save_results(incidents: List[Dict], output_file: str):
        """Save results to JSON file."""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(incidents, f, indent=2, default=str)
            
            print(f"\n✓ Results saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Bot - Correlation Engine Demo'
    )
    parser.add_argument(
        '--iocs',
        type=int,
        default=20,
        help='Number of sample IOCs to generate (default: 20)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Save results to JSON file'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    demo = CorrelationDemo(verbose=args.verbose)
    demo.run_demo(num_iocs=args.iocs, output_file=args.output)


if __name__ == '__main__':
    main()
