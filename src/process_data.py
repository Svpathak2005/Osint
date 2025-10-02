#!/usr/bin/env python3
"""
OSINT Data Processor CLI
Provides command-line interface for normalizing and aggregating OSINT data.
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from processors.normalizer import process_raw_files
from processors.aggregator import process_normalized_files
from processors.reporter import OSINTReporter
from processors.models import AggregatedIndicator


def setup_logging(log_level: str = 'INFO', log_file: str = None):
    """Set up logging configuration."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file) if log_file else logging.NullHandler()
        ]
    )
    
    # Suppress overly verbose loggers
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


def normalize_command(args):
    """Execute data normalization."""
    print(f"🔄 Starting data normalization...")
    print(f"📁 Raw data directory: {args.input_dir}")
    print(f"📁 Output directory: {args.output_dir}")
    
    if args.source:
        print(f"🎯 Processing only source: {args.source}")
    
    try:
        stats = process_raw_files(
            raw_data_dir=Path(args.input_dir),
            output_dir=Path(args.output_dir),
            specific_source=args.source
        )
        
        print(f"\n✅ Normalization completed successfully!")
        print(f"📊 Statistics:")
        print(f"   • Sources processed: {len(stats.sources_processed)}")
        print(f"   • Total raw records: {stats.total_raw_records}")
        print(f"   • Total normalized records: {stats.total_normalized_records}")
        print(f"   • Processing time: {stats.processing_end_time - stats.processing_start_time}")
        
        if stats.errors:
            print(f"⚠️  Errors encountered ({len(stats.errors)}):")
            for error in stats.errors[:5]:  # Show first 5 errors
                print(f"     • {error}")
            if len(stats.errors) > 5:
                print(f"     ... and {len(stats.errors) - 5} more errors")
    
    except Exception as e:
        print(f"❌ Normalization failed: {e}")
        sys.exit(1)


def aggregate_command(args):
    """Execute data aggregation."""
    print(f"🔄 Starting data aggregation...")
    print(f"📁 Normalized data directory: {args.input_dir}")
    print(f"📁 Output directory: {args.output_dir}")
    
    try:
        stats = process_normalized_files(
            input_dir=Path(args.input_dir),
            output_dir=Path(args.output_dir)
        )
        
        print(f"\n✅ Aggregation completed successfully!")
        print(f"📊 Statistics:")
        print(f"   • Sources processed: {len(stats.sources_processed)}")
        print(f"   • Total normalized records: {stats.total_normalized_records}")
        print(f"   • Total aggregated records: {stats.total_aggregated_records}")
        print(f"   • Processing time: {stats.processing_end_time - stats.processing_start_time}")
        
        if stats.errors:
            print(f"⚠️  Errors encountered ({len(stats.errors)}):")
            for error in stats.errors[:5]:  # Show first 5 errors
                print(f"     • {error}")
            if len(stats.errors) > 5:
                print(f"     ... and {len(stats.errors) - 5} more errors")
    
    except Exception as e:
        print(f"❌ Aggregation failed: {e}")
        sys.exit(1)


def pipeline_command(args):
    """Execute full data processing pipeline."""
    print(f"🚀 Starting full OSINT data processing pipeline...")
    
    # Define paths
    raw_dir = Path(args.raw_dir) if args.raw_dir else Path('data/raw')
    normalized_dir = Path(args.normalized_dir) if args.normalized_dir else Path('data/normalized')
    aggregated_dir = Path(args.aggregated_dir) if args.aggregated_dir else Path('data/aggregated')
    
    print(f"📁 Raw data: {raw_dir}")
    print(f"📁 Normalized data: {normalized_dir}")
    print(f"📁 Aggregated data: {aggregated_dir}")
    
    # Step 1: Normalization
    print(f"\n🔄 Step 1: Normalizing raw data...")
    try:
        norm_stats = process_raw_files(
            raw_data_dir=raw_dir,
            output_dir=normalized_dir,
            specific_source=args.source
        )
        print(f"✅ Normalization completed: {norm_stats.total_normalized_records} records")
    except Exception as e:
        print(f"❌ Normalization failed: {e}")
        sys.exit(1)
    
    # Step 2: Aggregation
    print(f"\n🔄 Step 2: Aggregating normalized data...")
    try:
        agg_stats = process_normalized_files(
            input_dir=normalized_dir,
            output_dir=aggregated_dir
        )
        print(f"✅ Aggregation completed: {agg_stats.total_aggregated_records} unique indicators")
    except Exception as e:
        print(f"❌ Aggregation failed: {e}")
        sys.exit(1)
    
    # Summary
    print(f"\n🎉 Pipeline completed successfully!")
    print(f"📊 Final Statistics:")
    print(f"   • Raw records processed: {norm_stats.total_raw_records}")
    print(f"   • Normalized records: {norm_stats.total_normalized_records}")
    print(f"   • Unique indicators: {agg_stats.total_aggregated_records}")
    print(f"   • Sources processed: {len(norm_stats.sources_processed)}")
    
    # Show aggregated data file
    latest_file = aggregated_dir / f"aggregated_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    summary_file = aggregated_dir / f"summary_{datetime.now().strftime('%Y-%m-%d')}.json"
    
    print(f"\n📄 Output files:")
    print(f"   • Aggregated data: {latest_file}")
    print(f"   • Summary report: {summary_file}")


def report_command(args):
    """Generate analysis reports."""
    print(f"📊 Generating OSINT analysis reports...")
    
    # Load aggregated data
    aggregated_dir = Path(args.input_dir)
    if not aggregated_dir.exists():
        print(f"❌ Aggregated data directory not found: {aggregated_dir}")
        sys.exit(1)
    
    # Find latest aggregated file
    aggregated_files = list(aggregated_dir.glob('aggregated_*.jsonl'))
    if not aggregated_files:
        print(f"❌ No aggregated data files found in {aggregated_dir}")
        sys.exit(1)
    
    latest_file = max(aggregated_files, key=lambda f: f.stat().st_mtime)
    print(f"📄 Using aggregated data: {latest_file}")
    
    # Load indicators
    indicators = []
    try:
        with open(latest_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    indicator = AggregatedIndicator(**data)
                    indicators.append(indicator)
        
        print(f"📊 Loaded {len(indicators)} aggregated indicators")
    except Exception as e:
        print(f"❌ Error loading aggregated data: {e}")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize reporter
    reporter = OSINTReporter()
    
    # Generate reports based on type
    if args.report_type in ['all', 'threat']:
        print(f"🔍 Generating threat intelligence report...")
        threat_file = output_dir / f"threat_report_{datetime.now().strftime('%Y-%m-%d')}.json"
        reporter.generate_threat_report(indicators, threat_file)
        print(f"✅ Threat report: {threat_file}")
    
    if args.report_type in ['all', 'ioc']:
        print(f"🎯 Generating IOC feed...")
        ioc_file = output_dir / f"ioc_feed_{datetime.now().strftime('%Y-%m-%d')}.json"
        from processors.models import Confidence
        min_conf = getattr(Confidence, args.min_confidence.upper())
        reporter.generate_ioc_feed(indicators, ioc_file, min_conf)
        print(f"✅ IOC feed: {ioc_file}")
    
    if args.report_type in ['all', 'dashboard']:
        print(f"📈 Generating summary dashboard...")
        dashboard_file = output_dir / f"dashboard_{datetime.now().strftime('%Y-%m-%d')}.json"
        reporter.generate_summary_dashboard(indicators, dashboard_file)
        print(f"✅ Dashboard: {dashboard_file}")
    
    print(f"\n🎉 Report generation completed!")
    print(f"📁 Reports saved to: {output_dir}")


def status_command(args):
    """Show data processing status and statistics."""
    print(f"📊 OSINT Data Status Report")
    print(f"=" * 50)
    
    # Check data directories
    base_dir = Path(args.data_dir) if args.data_dir else Path('data')
    raw_dir = base_dir / 'raw'
    normalized_dir = base_dir / 'normalized'
    aggregated_dir = base_dir / 'aggregated'
    
    # Raw data status
    print(f"\n📁 Raw Data ({raw_dir}):")
    if raw_dir.exists():
        raw_sources = [d.name for d in raw_dir.iterdir() if d.is_dir()]
        print(f"   • Sources available: {len(raw_sources)}")
        for source in raw_sources:
            source_files = list((raw_dir / source).glob('*.jsonl'))
            print(f"     - {source}: {len(source_files)} files")
    else:
        print(f"   ❌ Directory not found")
    
    # Normalized data status
    print(f"\n📁 Normalized Data ({normalized_dir}):")
    if normalized_dir.exists():
        norm_sources = [d.name for d in normalized_dir.iterdir() if d.is_dir()]
        print(f"   • Sources processed: {len(norm_sources)}")
        for source in norm_sources:
            norm_files = list((normalized_dir / source).glob('normalized_*.jsonl'))
            print(f"     - {source}: {len(norm_files)} files")
    else:
        print(f"   ❌ Directory not found")
    
    # Aggregated data status
    print(f"\n📁 Aggregated Data ({aggregated_dir}):")
    if aggregated_dir.exists():
        agg_files = list(aggregated_dir.glob('aggregated_*.jsonl'))
        summary_files = list(aggregated_dir.glob('summary_*.json'))
        print(f"   • Aggregated files: {len(agg_files)}")
        print(f"   • Summary files: {len(summary_files)}")
        
        # Show latest summary if available
        if summary_files:
            latest_summary = max(summary_files, key=lambda f: f.stat().st_mtime)
            try:
                import json
                with open(latest_summary, 'r') as f:
                    summary = json.load(f)
                
                print(f"\n📈 Latest Summary ({latest_summary.name}):")
                print(f"   • Total unique indicators: {summary.get('total_unique_indicators', 'N/A')}")
                print(f"   • High confidence threats: {summary.get('high_confidence_threats', 'N/A')}")
                print(f"   • Multi-source indicators: {summary.get('multi_source_indicators', 'N/A')}")
                
                if 'threat_distribution' in summary:
                    print(f"   • Threat distribution:")
                    for threat_level, count in summary['threat_distribution'].items():
                        print(f"     - {threat_level}: {count}")
                        
            except Exception as e:
                print(f"   ⚠️  Could not read summary file: {e}")
    else:
        print(f"   ❌ Directory not found")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='OSINT Data Processor - Normalize and aggregate threat intelligence data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normalize raw data from all sources
  python process_data.py normalize

  # Normalize data from specific source
  python process_data.py normalize --source shodan

  # Aggregate normalized data
  python process_data.py aggregate

  # Run full pipeline (normalize + aggregate)
  python process_data.py pipeline

  # Generate analysis reports
  python process_data.py report

  # Generate only IOC feed with high confidence
  python process_data.py report --report-type ioc --min-confidence high

  # Check data status
  python process_data.py status
        """
    )
    
    # Global arguments
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Set logging level')
    parser.add_argument('--log-file', help='Log to file instead of console')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Normalize command
    normalize_parser = subparsers.add_parser('normalize', help='Normalize raw OSINT data')
    normalize_parser.add_argument('--input-dir', default='data/raw',
                                 help='Raw data directory (default: data/raw)')
    normalize_parser.add_argument('--output-dir', default='data/normalized',
                                 help='Output directory (default: data/normalized)')
    normalize_parser.add_argument('--source', help='Process specific source only')
    
    # Aggregate command
    aggregate_parser = subparsers.add_parser('aggregate', help='Aggregate normalized data')
    aggregate_parser.add_argument('--input-dir', default='data/normalized',
                                 help='Normalized data directory (default: data/normalized)')
    aggregate_parser.add_argument('--output-dir', default='data/aggregated',
                                 help='Output directory (default: data/aggregated)')
    
    # Pipeline command
    pipeline_parser = subparsers.add_parser('pipeline', help='Run full processing pipeline')
    pipeline_parser.add_argument('--raw-dir', help='Raw data directory (default: data/raw)')
    pipeline_parser.add_argument('--normalized-dir', help='Normalized data directory (default: data/normalized)')
    pipeline_parser.add_argument('--aggregated-dir', help='Aggregated data directory (default: data/aggregated)')
    pipeline_parser.add_argument('--source', help='Process specific source only')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show data processing status')
    status_parser.add_argument('--data-dir', default='data',
                              help='Base data directory (default: data)')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate analysis reports')
    report_parser.add_argument('--input-dir', default='data/aggregated',
                              help='Aggregated data directory (default: data/aggregated)')
    report_parser.add_argument('--output-dir', default='reports',
                              help='Report output directory (default: reports)')
    report_parser.add_argument('--report-type', choices=['all', 'threat', 'ioc', 'dashboard'],
                              default='all', help='Type of report to generate (default: all)')
    report_parser.add_argument('--min-confidence', choices=['very_low', 'low', 'medium', 'high', 'very_high'],
                              default='medium', help='Minimum confidence for IOC feed (default: medium)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    
    # Execute command
    if args.command == 'normalize':
        normalize_command(args)
    elif args.command == 'aggregate':
        aggregate_command(args)
    elif args.command == 'pipeline':
        pipeline_command(args)
    elif args.command == 'status':
        status_command(args)
    elif args.command == 'report':
        report_command(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()