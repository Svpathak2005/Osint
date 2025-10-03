"""
OSINT Reporting Module
Generates analysis reports and visualizations from aggregated data.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import Counter, defaultdict

from .models import AggregatedIndicator, ThreatLevel, Confidence, IndicatorType

logger = logging.getLogger(__name__)


class OSINTReporter:
    """Generates various reports from aggregated OSINT data."""
    
    def __init__(self):
        self.threat_level_priority = {
            ThreatLevel.CRITICAL: 5,
            ThreatLevel.MALICIOUS: 4,
            ThreatLevel.SUSPICIOUS: 3,
            ThreatLevel.UNKNOWN: 2,
            ThreatLevel.BENIGN: 1
        }
    
    def generate_threat_report(self, indicators: List[AggregatedIndicator], output_file: Path) -> Dict[str, Any]:
        """Generate a comprehensive threat intelligence report."""
        report = {
            'report_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'total_indicators': len(indicators),
                'report_type': 'threat_intelligence',
                'version': '1.0'
            },
            'executive_summary': self._generate_executive_summary(indicators),
            'threat_analysis': self._analyze_threats(indicators),
            'geographic_analysis': self._analyze_geography(indicators),
            'network_analysis': self._analyze_networks(indicators),
            'source_analysis': self._analyze_sources(indicators),
            'high_priority_indicators': self._get_high_priority_indicators(indicators),
            'recommendations': self._generate_recommendations(indicators)
        }
        
        # Save report
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Threat report generated: {output_file}")
        return report
    
    def generate_ioc_feed(self, indicators: List[AggregatedIndicator], output_file: Path, 
                         min_confidence: Confidence = Confidence.MEDIUM) -> Dict[str, Any]:
        """Generate an IOC feed for security tools."""
        # Filter high-confidence malicious indicators
        iocs = []
        
        for indicator in indicators:
            if (indicator.consensus_threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL] 
                and indicator.consensus_confidence.value >= min_confidence.value):
                
                ioc_entry = {
                    'indicator': indicator.indicator,
                    'type': indicator.indicator_type.value,
                    'threat_level': indicator.consensus_threat_level.value,
                    'confidence': indicator.consensus_confidence.value,
                    'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None,
                    'last_updated': indicator.last_updated.isoformat(),
                    'sources': len(indicator.normalized_sources),
                    'malicious_votes': indicator.malicious_votes,
                    'reputation_score': indicator.overall_reputation_score,
                    'tags': []
                }
                
                # Add threat intelligence tags
                if indicator.aggregated_threats:
                    threats = indicator.aggregated_threats
                    ioc_entry['tags'].extend(threats.malware_families)
                    ioc_entry['tags'].extend(threats.attack_types)
                    ioc_entry['tags'].extend(threats.threat_actors)
                
                # Add location tags
                if indicator.most_likely_location:
                    loc = indicator.most_likely_location
                    if loc.country:
                        ioc_entry['tags'].append(f"country:{loc.country}")
                    if loc.city:
                        ioc_entry['tags'].append(f"city:{loc.city}")
                
                # Add network tags
                if indicator.primary_network:
                    net = indicator.primary_network
                    if net.asn:
                        ioc_entry['tags'].append(f"asn:{net.asn}")
                    if net.organization:
                        ioc_entry['tags'].append(f"org:{net.organization}")
                
                iocs.append(ioc_entry)
        
        # Sort by threat level and confidence
        iocs.sort(key=lambda x: (
            self.threat_level_priority.get(ThreatLevel(x['threat_level']), 0),
            x['confidence'],
            x['reputation_score']
        ), reverse=True)
        
        feed = {
            'feed_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'feed_type': 'ioc_feed',
                'version': '1.0',
                'min_confidence': min_confidence.value,
                'total_iocs': len(iocs)
            },
            'indicators': iocs
        }
        
        # Save feed
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(feed, f, indent=2, default=str)
        
        logger.info(f"IOC feed generated with {len(iocs)} indicators: {output_file}")
        return feed
    
    def generate_summary_dashboard(self, indicators: List[AggregatedIndicator], output_file: Path) -> Dict[str, Any]:
        """Generate a summary dashboard with key metrics and charts."""
        dashboard = {
            'dashboard_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'total_indicators': len(indicators),
                'dashboard_type': 'summary',
                'version': '1.0'
            },
            'key_metrics': self._calculate_key_metrics(indicators),
            'threat_distribution': self._get_threat_distribution(indicators),
            'confidence_distribution': self._get_confidence_distribution(indicators),
            'indicator_type_distribution': self._get_indicator_type_distribution(indicators),
            'geographic_distribution': self._get_geographic_distribution(indicators),
            'temporal_analysis': self._get_temporal_analysis(indicators),
            'source_coverage': self._get_source_coverage(indicators),
            'network_analysis': self._get_network_distribution(indicators)
        }
        
        # Save dashboard
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dashboard, f, indent=2, default=str)
        
        logger.info(f"Summary dashboard generated: {output_file}")
        return dashboard
    
    def _generate_executive_summary(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Generate executive summary of threat landscape."""
        total = len(indicators)
        
        # Count threat levels
        threat_counts = Counter()
        high_confidence_threats = 0
        
        for indicator in indicators:
            threat_counts[indicator.consensus_threat_level] += 1
            if (indicator.consensus_threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL] 
                and indicator.consensus_confidence in [Confidence.HIGH, Confidence.VERY_HIGH]):
                high_confidence_threats += 1
        
        # Calculate percentages
        malicious_pct = ((threat_counts[ThreatLevel.MALICIOUS] + threat_counts[ThreatLevel.CRITICAL]) / total * 100) if total > 0 else 0
        
        return {
            'total_indicators_analyzed': total,
            'high_confidence_threats': high_confidence_threats,
            'malicious_percentage': round(malicious_pct, 2),
            'threat_breakdown': {
                'critical': threat_counts[ThreatLevel.CRITICAL],
                'malicious': threat_counts[ThreatLevel.MALICIOUS],
                'suspicious': threat_counts[ThreatLevel.SUSPICIOUS],
                'unknown': threat_counts[ThreatLevel.UNKNOWN],
                'benign': threat_counts[ThreatLevel.BENIGN]
            },
            'key_findings': self._generate_key_findings(indicators)
        }
    
    def _generate_key_findings(self, indicators: List[AggregatedIndicator]) -> List[str]:
        """Generate key findings from the data."""
        findings = []
        
        # Top threats
        critical_indicators = [i for i in indicators if i.consensus_threat_level == ThreatLevel.CRITICAL]
        if critical_indicators:
            findings.append(f"🚨 {len(critical_indicators)} indicators classified as CRITICAL threat level")
        
        # Multi-source validation
        multi_source = [i for i in indicators if i.total_sources > 2]
        if multi_source:
            findings.append(f"✅ {len(multi_source)} indicators validated by multiple sources (>2 sources)")
        
        # Geographic concentration
        countries = Counter()
        for indicator in indicators:
            if indicator.most_likely_location and indicator.most_likely_location.country:
                countries[indicator.most_likely_location.country] += 1
        
        if countries:
            top_country = countries.most_common(1)[0]
            findings.append(f"🌍 Geographic concentration: {top_country[0]} ({top_country[1]} indicators)")
        
        # Common malware families
        malware_families = Counter()
        for indicator in indicators:
            if indicator.aggregated_threats:
                malware_families.update(indicator.aggregated_threats.malware_families)
        
        if malware_families:
            top_malware = malware_families.most_common(1)[0]
            findings.append(f"🦠 Most common malware family: {top_malware[0]} ({top_malware[1]} indicators)")
        
        # Data freshness
        recent_indicators = [i for i in indicators 
                           if i.last_updated and (datetime.utcnow() - i.last_updated).days <= 1]
        if recent_indicators:
            findings.append(f"🕐 {len(recent_indicators)} indicators updated within the last 24 hours")
        
        return findings
    
    def _analyze_threats(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Analyze threat patterns."""
        malware_families = Counter()
        attack_types = Counter()
        threat_actors = Counter()
        campaigns = Counter()
        
        for indicator in indicators:
            if indicator.aggregated_threats:
                threats = indicator.aggregated_threats
                malware_families.update(threats.malware_families)
                attack_types.update(threats.attack_types)
                threat_actors.update(threats.threat_actors)
                campaigns.update(threats.campaigns)
        
        return {
            'top_malware_families': dict(malware_families.most_common(10)),
            'top_attack_types': dict(attack_types.most_common(10)),
            'top_threat_actors': dict(threat_actors.most_common(10)),
            'active_campaigns': dict(campaigns.most_common(5))
        }
    
    def _analyze_geography(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Analyze geographic distribution of threats."""
        countries = Counter()
        cities = Counter()
        regions = Counter()
        
        for indicator in indicators:
            if indicator.most_likely_location:
                loc = indicator.most_likely_location
                if loc.country:
                    countries[loc.country] += 1
                if loc.city:
                    cities[f"{loc.city}, {loc.country}"] += 1
                if loc.region:
                    regions[loc.region] += 1
        
        return {
            'top_countries': dict(countries.most_common(15)),
            'top_cities': dict(cities.most_common(10)),
            'top_regions': dict(regions.most_common(10))
        }
    
    def _analyze_networks(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Analyze network-related patterns."""
        asns = Counter()
        organizations = Counter()
        
        for indicator in indicators:
            if indicator.primary_network:
                net = indicator.primary_network
                if net.asn:
                    asns[f"AS{net.asn}"] += 1
                if net.organization:
                    organizations[net.organization] += 1
        
        return {
            'top_asns': dict(asns.most_common(10)),
            'top_organizations': dict(organizations.most_common(10))
        }
    
    def _analyze_sources(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Analyze source coverage and reliability."""
        source_coverage = Counter()
        source_agreement = defaultdict(list)
        
        for indicator in indicators:
            source_coverage[indicator.total_sources] += 1
            
            # Analyze source agreement for multi-source indicators
            if indicator.total_sources > 1:
                sources = set()
                for norm_ind in indicator.normalized_sources:
                    if norm_ind.sources:
                        sources.add(norm_ind.sources[0].name)
                
                threat_level = indicator.consensus_threat_level.value
                source_agreement[threat_level].append(indicator.total_sources)
        
        # Calculate average sources per threat level
        avg_sources_by_threat = {}
        for threat_level, source_counts in source_agreement.items():
            avg_sources_by_threat[threat_level] = sum(source_counts) / len(source_counts) if source_counts else 0
        
        return {
            'source_coverage_distribution': dict(source_coverage),
            'average_sources_per_threat_level': avg_sources_by_threat,
            'multi_source_indicators': len([i for i in indicators if i.total_sources > 1])
        }
    
    def _get_high_priority_indicators(self, indicators: List[AggregatedIndicator], limit: int = 20) -> List[Dict[str, Any]]:
        """Get high priority indicators for immediate attention."""
        # Filter and sort by priority
        priority_indicators = []
        
        for indicator in indicators:
            # Calculate priority score
            priority_score = 0
            
            # Threat level weight
            if indicator.consensus_threat_level == ThreatLevel.CRITICAL:
                priority_score += 100
            elif indicator.consensus_threat_level == ThreatLevel.MALICIOUS:
                priority_score += 80
            elif indicator.consensus_threat_level == ThreatLevel.SUSPICIOUS:
                priority_score += 40
            
            # Confidence weight
            if indicator.consensus_confidence == Confidence.VERY_HIGH:
                priority_score += 50
            elif indicator.consensus_confidence == Confidence.HIGH:
                priority_score += 30
            elif indicator.consensus_confidence == Confidence.MEDIUM:
                priority_score += 15
            
            # Multi-source validation weight
            priority_score += min(indicator.total_sources * 10, 50)
            
            # Recent activity weight
            if indicator.last_updated and (datetime.utcnow() - indicator.last_updated).days <= 1:
                priority_score += 25
            
            priority_indicators.append({
                'indicator': indicator.indicator,
                'type': indicator.indicator_type.value,
                'threat_level': indicator.consensus_threat_level.value,
                'confidence': indicator.consensus_confidence.value,
                'priority_score': priority_score,
                'sources': indicator.total_sources,
                'reputation_score': indicator.overall_reputation_score,
                'last_updated': indicator.last_updated.isoformat() if indicator.last_updated else None,
                'malware_families': indicator.aggregated_threats.malware_families if indicator.aggregated_threats else [],
                'location': f"{indicator.most_likely_location.city}, {indicator.most_likely_location.country}" if indicator.most_likely_location else None
            })
        
        # Sort by priority score and return top indicators
        priority_indicators.sort(key=lambda x: x['priority_score'], reverse=True)
        return priority_indicators[:limit]
    
    def _generate_recommendations(self, indicators: List[AggregatedIndicator]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Check for critical threats
        critical_threats = [i for i in indicators if i.consensus_threat_level == ThreatLevel.CRITICAL]
        if critical_threats:
            recommendations.append(f"URGENT: Immediately block {len(critical_threats)} indicators classified as CRITICAL threats")
        
        # Check for high-confidence malicious indicators
        high_conf_malicious = [i for i in indicators 
                             if i.consensus_threat_level == ThreatLevel.MALICIOUS 
                             and i.consensus_confidence in [Confidence.HIGH, Confidence.VERY_HIGH]]
        if high_conf_malicious:
            recommendations.append(f"Add {len(high_conf_malicious)} high-confidence malicious indicators to blocklists")
        
        # Check for geographic concentration
        countries = Counter()
        for indicator in indicators:
            if (indicator.most_likely_location and indicator.most_likely_location.country 
                and indicator.consensus_threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL]):
                countries[indicator.most_likely_location.country] += 1
        
        if countries:
            top_country = countries.most_common(1)[0]
            if top_country[1] > 10:  # Threshold for geographic monitoring
                recommendations.append(f"Consider enhanced monitoring of traffic from {top_country[0]} ({top_country[1]} malicious indicators)")
        
        # Check for suspicious indicators needing investigation
        suspicious = [i for i in indicators if i.consensus_threat_level == ThreatLevel.SUSPICIOUS]
        if suspicious:
            recommendations.append(f"Investigate {len(suspicious)} suspicious indicators for potential threats")
        
        # Check for data freshness
        stale_data = [i for i in indicators 
                     if i.last_updated and (datetime.utcnow() - i.last_updated).days > 7]
        if stale_data:
            recommendations.append(f"Update threat intelligence for {len(stale_data)} indicators with stale data (>7 days old)")
        
        return recommendations
    
    def _calculate_key_metrics(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Calculate key performance metrics."""
        total = len(indicators)
        
        # Threat distribution
        threats = Counter(i.consensus_threat_level for i in indicators)
        
        # Confidence distribution
        confidence = Counter(i.consensus_confidence for i in indicators)
        
        # Source coverage
        multi_source = len([i for i in indicators if i.total_sources > 1])
        
        # Data freshness
        now = datetime.utcnow()
        fresh_data = len([i for i in indicators if i.last_updated and (now - i.last_updated).days <= 1])
        recent_data = len([i for i in indicators if i.last_updated and (now - i.last_updated).days <= 7])
        
        return {
            'total_indicators': total,
            'threat_distribution': {level.value: count for level, count in threats.items()},
            'confidence_distribution': {conf.value: count for conf, count in confidence.items()},
            'multi_source_validation_rate': round((multi_source / total * 100) if total > 0 else 0, 2),
            'data_freshness': {
                'updated_today': fresh_data,
                'updated_this_week': recent_data,
                'freshness_rate': round((recent_data / total * 100) if total > 0 else 0, 2)
            }
        }
    
    def _get_threat_distribution(self, indicators: List[AggregatedIndicator]) -> Dict[str, int]:
        """Get threat level distribution."""
        return dict(Counter(i.consensus_threat_level.value for i in indicators))
    
    def _get_confidence_distribution(self, indicators: List[AggregatedIndicator]) -> Dict[str, int]:
        """Get confidence level distribution."""
        return dict(Counter(i.consensus_confidence.value for i in indicators))
    
    def _get_indicator_type_distribution(self, indicators: List[AggregatedIndicator]) -> Dict[str, int]:
        """Get indicator type distribution."""
        return dict(Counter(i.indicator_type.value for i in indicators))
    
    def _get_geographic_distribution(self, indicators: List[AggregatedIndicator]) -> Dict[str, int]:
        """Get geographic distribution."""
        countries = Counter()
        for indicator in indicators:
            if indicator.most_likely_location and indicator.most_likely_location.country:
                countries[indicator.most_likely_location.country] += 1
        return dict(countries.most_common(10))
    
    def _get_temporal_analysis(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Get temporal analysis of indicators."""
        now = datetime.utcnow()
        
        # Time buckets
        buckets = {
            'last_24h': 0,
            'last_week': 0,
            'last_month': 0,
            'older': 0
        }
        
        for indicator in indicators:
            if indicator.last_updated:
                age = (now - indicator.last_updated).days
                if age == 0:
                    buckets['last_24h'] += 1
                elif age <= 7:
                    buckets['last_week'] += 1
                elif age <= 30:
                    buckets['last_month'] += 1
                else:
                    buckets['older'] += 1
        
        return buckets
    
    def _get_source_coverage(self, indicators: List[AggregatedIndicator]) -> Dict[str, int]:
        """Get source coverage distribution."""
        return dict(Counter(i.total_sources for i in indicators))
    
    def _get_network_distribution(self, indicators: List[AggregatedIndicator]) -> Dict[str, Any]:
        """Get network distribution analysis."""
        asns = Counter()
        orgs = Counter()
        
        for indicator in indicators:
            if indicator.primary_network:
                net = indicator.primary_network
                if net.asn:
                    asns[f"AS{net.asn}"] += 1
                if net.organization:
                    orgs[net.organization] += 1
        
        return {
            'top_asns': dict(asns.most_common(5)),
            'top_organizations': dict(orgs.most_common(5))
        }
    
    def generate_charts(self) -> bool:
        """Generate static visualization charts from aggregated data."""
        try:
            import matplotlib.pyplot as plt
            import pandas as pd
            
            # Find latest aggregated data
            aggregated_dir = Path('data/aggregated')
            if not aggregated_dir.exists():
                logger.error("No aggregated data directory found")
                return False
            
            aggregated_files = list(aggregated_dir.glob('aggregated_*.jsonl'))
            if not aggregated_files:
                logger.error("No aggregated data files found")
                return False
            
            latest_file = max(aggregated_files, key=lambda f: f.stat().st_mtime)
            
            # Load indicators
            indicators = []
            with open(latest_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            indicator = AggregatedIndicator(**data)
                            indicators.append(indicator)
                        except Exception as e:
                            logger.error(f"Error loading indicator: {e}")
            
            if not indicators:
                logger.error("No indicators loaded")
                return False
            
            # Create charts directory
            charts_dir = Path('reports/charts')
            charts_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate charts
            self._create_threat_distribution_chart(indicators, charts_dir)
            self._create_confidence_chart(indicators, charts_dir)
            self._create_geographic_chart(indicators, charts_dir)
            self._create_source_analysis_chart(indicators, charts_dir)
            
            logger.info(f"Charts generated in {charts_dir}")
            return True
            
        except ImportError:
            logger.error("matplotlib and pandas required for chart generation")
            return False
        except Exception as e:
            logger.error(f"Error generating charts: {e}")
            return False
    
    def _create_threat_distribution_chart(self, indicators: List[AggregatedIndicator], output_dir: Path):
        """Create threat level distribution chart."""
        import matplotlib.pyplot as plt
        
        threat_counts = Counter(i.consensus_threat_level.value for i in indicators)
        
        plt.figure(figsize=(10, 6))
        colors = {
            'critical': '#dc3545',
            'malicious': '#fd7e14', 
            'suspicious': '#ffc107',
            'unknown': '#6c757d',
            'benign': '#28a745'
        }
        
        threat_labels = list(threat_counts.keys())
        threat_values = list(threat_counts.values())
        chart_colors = [colors.get(label, '#6c757d') for label in threat_labels]
        
        plt.pie(threat_values, labels=threat_labels, colors=chart_colors, autopct='%1.1f%%')
        plt.title('Threat Level Distribution', fontsize=16, fontweight='bold')
        plt.savefig(output_dir / 'threat_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_confidence_chart(self, indicators: List[AggregatedIndicator], output_dir: Path):
        """Create confidence level chart."""
        import matplotlib.pyplot as plt
        
        confidence_counts = Counter(i.consensus_confidence.value for i in indicators)
        
        plt.figure(figsize=(10, 6))
        plt.bar(confidence_counts.keys(), confidence_counts.values(), color='steelblue')
        plt.title('Confidence Level Distribution', fontsize=16, fontweight='bold')
        plt.xlabel('Confidence Level')
        plt.ylabel('Number of Indicators')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(output_dir / 'confidence_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_geographic_chart(self, indicators: List[AggregatedIndicator], output_dir: Path):
        """Create geographic distribution chart."""
        import matplotlib.pyplot as plt
        
        countries = []
        for indicator in indicators:
            if indicator.most_likely_location and indicator.most_likely_location.country:
                countries.append(indicator.most_likely_location.country)
        
        if not countries:
            return
        
        country_counts = Counter(countries).most_common(15)
        
        plt.figure(figsize=(12, 8))
        countries, counts = zip(*country_counts)
        plt.barh(range(len(countries)), counts, color='lightcoral')
        plt.yticks(range(len(countries)), countries)
        plt.title('Top 15 Countries by Indicator Count', fontsize=16, fontweight='bold')
        plt.xlabel('Number of Indicators')
        plt.tight_layout()
        plt.savefig(output_dir / 'geographic_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_source_analysis_chart(self, indicators: List[AggregatedIndicator], output_dir: Path):
        """Create source coverage analysis chart."""
        import matplotlib.pyplot as plt
        
        source_counts = Counter(i.total_sources for i in indicators)
        
        plt.figure(figsize=(10, 6))
        plt.bar(source_counts.keys(), source_counts.values(), color='mediumseagreen')
        plt.title('Source Coverage Distribution', fontsize=16, fontweight='bold')
        plt.xlabel('Number of Sources per Indicator')
        plt.ylabel('Number of Indicators')
        plt.tight_layout()
        plt.savefig(output_dir / 'source_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()