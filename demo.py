#!/usr/bin/env python3
"""
OSINT Data Pipeline Demo
Demonstrates the complete data processing pipeline with sample data.
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.processors.models import (
    IndicatorType, ThreatLevel, Confidence,
    SourceData, ReputationScore, GeolocationData, NetworkData, ThreatIntelligence
)


def create_sample_data():
    """Create sample raw data for demonstration."""
    print("🔧 Creating sample OSINT data for demonstration...")
    
    # Create data directories
    data_dir = Path('data')
    raw_dir = data_dir / 'raw'
    
    # Sample data for different sources
    sample_data = {
        'shodan': [
            {
                'ip': '192.168.1.100',
                'hostnames': ['test.example.com'],
                'org': 'Example Organization',
                'isp': 'Example ISP',
                'asn': 'AS12345',
                'country_name': 'United States',
                'city': 'New York',
                'region_code': 'NY',
                'latitude': 40.7128,
                'longitude': -74.0060,
                'ports': [80, 443, 22],
                'vulns': ['CVE-2021-44228'],
                'last_update': '2025-01-02T10:00:00Z'
            },
            {
                'ip': '10.0.0.50',
                'org': 'Malicious Network Inc',
                'asn': 'AS99999',
                'country_name': 'Unknown',
                'ports': [25, 587, 2525],
                'tags': ['malware', 'botnet'],
                'last_update': '2025-01-02T09:30:00Z'
            }
        ],
        'virustotal': [
            {
                'id': '192.168.1.100',
                'type': 'ip_address',
                'attributes': {
                    'reputation': -5,
                    'harmless': 75,
                    'malicious': 5,
                    'suspicious': 2,
                    'undetected': 8,
                    'country': 'US',
                    'as_owner': 'Example Organization',
                    'asn': 12345,
                    'last_analysis_stats': {
                        'harmless': 75,
                        'malicious': 5,
                        'suspicious': 2,
                        'undetected': 8,
                        'timeout': 0
                    }
                }
            },
            {
                'id': '10.0.0.50',
                'type': 'ip_address',
                'attributes': {
                    'reputation': -85,
                    'harmless': 10,
                    'malicious': 75,
                    'suspicious': 10,
                    'undetected': 5,
                    'country': 'XX',
                    'as_owner': 'Malicious Network Inc',
                    'asn': 99999,
                    'last_analysis_stats': {
                        'harmless': 10,
                        'malicious': 75,
                        'suspicious': 10,
                        'undetected': 5,
                        'timeout': 0
                    }
                }
            }
        ],
        'abuseipdb': [
            {
                'ipAddress': '192.168.1.100',
                'abuseConfidencePercentage': 15,
                'countryCode': 'US',
                'usageType': 'Commercial',
                'isp': 'Example ISP',
                'domain': 'example.com',
                'totalReports': 2,
                'numDistinctUsers': 2,
                'lastReportedAt': '2025-01-01T15:30:00Z'
            },
            {
                'ipAddress': '10.0.0.50',
                'abuseConfidencePercentage': 95,
                'countryCode': None,
                'usageType': 'hosting',
                'isp': 'Malicious Network Inc',
                'totalReports': 150,
                'numDistinctUsers': 45,
                'lastReportedAt': '2025-01-02T08:45:00Z'
            }
        ],
        'otx': [
            {
                'indicator': '192.168.1.100',
                'type': 'IPv4',
                'pulse_info': {
                    'count': 1,
                    'pulses': [
                        {
                            'name': 'Suspicious Activity',
                            'description': 'Low level suspicious activity detected',
                            'tags': ['suspicious'],
                            'malware_families': [],
                            'attack_ids': [],
                            'industries': [],
                            'created': '2025-01-01T12:00:00Z'
                        }
                    ]
                },
                'validation': [
                    {
                        'source': 'otx',
                        'message': 'Valid IP address'
                    }
                ]
            },
            {
                'indicator': '10.0.0.50',
                'type': 'IPv4',
                'pulse_info': {
                    'count': 3,
                    'pulses': [
                        {
                            'name': 'Botnet C2 Infrastructure',
                            'description': 'Known botnet command and control server',
                            'tags': ['malware', 'botnet', 'c2'],
                            'malware_families': ['Zeus', 'Emotet'],
                            'attack_ids': ['T1071', 'T1090'],
                            'industries': ['financial', 'healthcare'],
                            'created': '2025-01-02T06:00:00Z'
                        }
                    ]
                }
            }
        ]
    }
    
    # Create sample files
    for source, data in sample_data.items():
        source_dir = raw_dir / source
        source_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = source_dir / '2025-01-02.jsonl'
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in data:
                f.write(json.dumps(record) + '\n')
        
        print(f"   ✅ Created {source} sample data: {output_file}")
    
    print(f"📁 Sample data created in: {raw_dir}")
    return raw_dir


def run_demo():
    """Run the complete data processing pipeline demo."""
    print("🚀 OSINT Data Processing Pipeline Demo")
    print("=" * 50)
    
    try:
        # Step 1: Create sample data
        raw_dir = create_sample_data()
        
        # Step 2: Import and run normalization
        print(f"\n🔄 Step 1: Normalizing raw data...")
        from src.processors.normalizer import process_raw_files
        
        normalized_dir = Path('data/normalized')
        norm_stats = process_raw_files(raw_dir, normalized_dir)
        
        print(f"✅ Normalization completed:")
        print(f"   • Records processed: {norm_stats.get('processed', 0)}")
        print(f"   • Records normalized: {norm_stats.get('normalized', 0)}")
        print(f"   • Errors: {norm_stats.get('errors', 0)}")
        
        # Step 3: Run aggregation
        print(f"\n🔄 Step 2: Aggregating normalized data...")
        from src.processors.aggregator import process_normalized_files
        
        aggregated_dir = Path('data/aggregated')
        agg_stats = process_normalized_files(normalized_dir, aggregated_dir)
        
        print(f"✅ Aggregation completed:")
        print(f"   • Normalized records: {agg_stats.total_normalized_records}")
        print(f"   • Unique indicators: {agg_stats.total_aggregated_records}")
        
        # Step 4: Generate reports
        print(f"\n🔄 Step 3: Generating analysis reports...")
        from src.processors.reporter import OSINTReporter
        from src.processors.models import AggregatedIndicator
        
        # Load aggregated data
        aggregated_file = aggregated_dir / f"aggregated_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        indicators = []
        
        with open(aggregated_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    indicator = AggregatedIndicator(**data)
                    indicators.append(indicator)
        
        # Generate reports
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        reporter = OSINTReporter()
        
        # Threat report
        threat_file = reports_dir / f"threat_report_{datetime.now().strftime('%Y-%m-%d')}.json"
        reporter.generate_threat_report(indicators, threat_file)
        
        # IOC feed
        ioc_file = reports_dir / f"ioc_feed_{datetime.now().strftime('%Y-%m-%d')}.json"
        reporter.generate_ioc_feed(indicators, ioc_file)
        
        # Dashboard
        dashboard_file = reports_dir / f"dashboard_{datetime.now().strftime('%Y-%m-%d')}.json"
        reporter.generate_summary_dashboard(indicators, dashboard_file)
        
        print(f"✅ Reports generated:")
        print(f"   • Threat report: {threat_file}")
        print(f"   • IOC feed: {ioc_file}")
        print(f"   • Dashboard: {dashboard_file}")
        
        # Step 5: Show summary
        print(f"\n🎉 Demo completed successfully!")
        print(f"📊 Final Statistics:")
        print(f"   • Raw records processed: {norm_stats.get('processed', 0)}")
        print(f"   • Normalized records: {norm_stats.get('normalized', 0)}")
        print(f"   • Unique indicators: {agg_stats.total_aggregated_records}")
        print(f"   • Reports generated: 3")
        
        print(f"\n📁 Output directories:")
        print(f"   • Raw data: {raw_dir}")
        print(f"   • Normalized data: {normalized_dir}")
        print(f"   • Aggregated data: {aggregated_dir}")
        print(f"   • Reports: {reports_dir}")
        
        # Show some sample results
        print(f"\n📈 Sample Results:")
        for indicator in indicators[:2]:  # Show first 2 indicators
            print(f"   • {indicator.indicator} ({indicator.indicator_type.value})")
            print(f"     - Threat Level: {indicator.consensus_threat_level.value}")
            print(f"     - Confidence: {indicator.consensus_confidence.value}")
            print(f"     - Sources: {indicator.total_sources}")
            print(f"     - Reputation: {indicator.overall_reputation_score:.1f}")
            if indicator.most_likely_location:
                loc = indicator.most_likely_location
                print(f"     - Location: {loc.city}, {loc.country}")
        
        print(f"\n💡 Next Steps:")
        print(f"   • Review generated reports in the 'reports' directory")
        print(f"   • Use the CLI tool: python src/process_data.py --help")
        print(f"   • Add your real API keys to .env file for live data collection")
        print(f"   • Customize normalization rules for your specific use case")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    run_demo()