"""
Data aggregation engine for combining normalized OSINT data.
Aggregates data from multiple sources for each indicator.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import defaultdict, Counter

from .models import (
    NormalizedIndicator, AggregatedIndicator, IndicatorType,
    ThreatLevel, Confidence, GeolocationData, NetworkData,
    ThreatIntelligence, ProcessingStats
)

logger = logging.getLogger(__name__)


class DataAggregator:
    """Aggregates normalized data from multiple sources."""
    
    def __init__(self):
        self.threat_level_weights = {
            ThreatLevel.BENIGN: 0,
            ThreatLevel.UNKNOWN: 25,
            ThreatLevel.SUSPICIOUS: 50,
            ThreatLevel.MALICIOUS: 100,
            ThreatLevel.CRITICAL: 100
        }
        
        self.confidence_weights = {
            Confidence.VERY_LOW: 0.1,
            Confidence.LOW: 0.3,
            Confidence.MEDIUM: 0.5,
            Confidence.HIGH: 0.8,
            Confidence.VERY_HIGH: 1.0
        }
    
    def aggregate_indicators(self, normalized_indicators: List[NormalizedIndicator]) -> List[AggregatedIndicator]:
        """Aggregate multiple normalized indicators by indicator value."""
        # Group indicators by their value
        indicator_groups = defaultdict(list)
        
        for indicator in normalized_indicators:
            indicator_groups[indicator.indicator].append(indicator)
        
        # Aggregate each group
        aggregated = []
        for indicator_value, indicators in indicator_groups.items():
            try:
                aggregated_indicator = self._aggregate_single_indicator(indicator_value, indicators)
                if aggregated_indicator:
                    aggregated.append(aggregated_indicator)
            except Exception as e:
                logger.error(f"Error aggregating indicator {indicator_value}: {e}")
        
        return aggregated
    
    def _aggregate_single_indicator(self, indicator_value: str, indicators: List[NormalizedIndicator]) -> Optional[AggregatedIndicator]:
        """Aggregate data for a single indicator from multiple sources."""
        if not indicators:
            return None
        
        # Get the indicator type (should be consistent across sources)
        indicator_type = indicators[0].indicator_type
        
        # Calculate consensus threat level
        consensus_threat_level, threat_confidence = self._calculate_consensus_threat_level(indicators)
        
        # Calculate overall reputation score
        overall_reputation = self._calculate_overall_reputation(indicators)
        
        # Get most likely location
        most_likely_location, location_confidence = self._determine_consensus_location(indicators)
        
        # Get primary network information
        primary_network = self._determine_primary_network(indicators)
        
        # Aggregate threat intelligence
        aggregated_threats = self._aggregate_threat_intelligence(indicators)
        
        # Count votes
        votes = self._count_threat_votes(indicators)
        
        # Find time boundaries
        first_seen = min(
            (ind.first_seen for ind in indicators if ind.first_seen),
            default=min(ind.last_seen for ind in indicators if ind.last_seen)
        )
        
        last_updated = max(
            (ind.last_seen for ind in indicators if ind.last_seen),
            default=datetime.utcnow()
        )
        
        # Identify conflicts
        conflicting_data = self._identify_conflicts(indicators)
        
        # Generate analysis notes
        analysis_notes = self._generate_analysis_notes(indicators, votes)
        
        return AggregatedIndicator(
            indicator=indicator_value,
            indicator_type=indicator_type,
            consensus_threat_level=consensus_threat_level,
            consensus_confidence=threat_confidence,
            overall_reputation_score=overall_reputation,
            most_likely_location=most_likely_location,
            location_confidence=location_confidence,
            primary_network=primary_network,
            aggregated_threats=aggregated_threats,
            total_sources=len(indicators),
            malicious_votes=votes['malicious'],
            benign_votes=votes['benign'],
            suspicious_votes=votes['suspicious'],
            first_seen=first_seen,
            last_updated=last_updated,
            normalized_sources=indicators,
            analysis_notes=analysis_notes,
            conflicting_data=conflicting_data
        )
    
    def _calculate_consensus_threat_level(self, indicators: List[NormalizedIndicator]) -> tuple[ThreatLevel, Confidence]:
        """Calculate consensus threat level using weighted voting."""
        weighted_scores = []
        total_weight = 0
        
        for indicator in indicators:
            if indicator.threat_intelligence:
                threat_level = indicator.threat_intelligence.threat_level
                confidence = indicator.threat_intelligence.confidence
                
                score = self.threat_level_weights.get(threat_level, 25)
                weight = self.confidence_weights.get(confidence, 0.5)
                
                weighted_scores.append(score * weight)
                total_weight += weight
        
        if not weighted_scores:
            return ThreatLevel.UNKNOWN, Confidence.LOW
        
        # Calculate weighted average
        avg_score = sum(weighted_scores) / total_weight if total_weight > 0 else 25
        
        # Determine consensus threat level
        if avg_score >= 90:
            consensus_level = ThreatLevel.CRITICAL
        elif avg_score >= 70:
            consensus_level = ThreatLevel.MALICIOUS
        elif avg_score >= 40:
            consensus_level = ThreatLevel.SUSPICIOUS
        elif avg_score >= 10:
            consensus_level = ThreatLevel.UNKNOWN
        else:
            consensus_level = ThreatLevel.BENIGN
        
        # Determine confidence based on source agreement
        confidence_level = Confidence.MEDIUM
        if total_weight >= 3.0:  # High weight from multiple high-confidence sources
            confidence_level = Confidence.HIGH
        elif total_weight >= 1.5:
            confidence_level = Confidence.MEDIUM
        else:
            confidence_level = Confidence.LOW
        
        return consensus_level, confidence_level
    
    def _calculate_overall_reputation(self, indicators: List[NormalizedIndicator]) -> float:
        """Calculate overall reputation score (0-100 scale)."""
        scores = []
        weights = []
        
        for indicator in indicators:
            for rep_score in indicator.reputation_scores:
                # Normalize score to 0-100 scale
                normalized_score = (rep_score.score / rep_score.max_score) * 100
                scores.append(normalized_score)
                
                # Weight based on source reliability
                source_weight = 1.0
                if 'virustotal' in rep_score.source:
                    source_weight = 1.2
                elif 'abuseipdb' in rep_score.source:
                    source_weight = 1.1
                elif 'greynoise' in rep_score.source:
                    source_weight = 1.1
                
                weights.append(source_weight)
        
        if not scores:
            return 0.0
        
        # Calculate weighted average
        if weights:
            weighted_sum = sum(s * w for s, w in zip(scores, weights))
            total_weight = sum(weights)
            return weighted_sum / total_weight
        else:
            return sum(scores) / len(scores)
    
    def _determine_consensus_location(self, indicators: List[NormalizedIndicator]) -> tuple[Optional[GeolocationData], Confidence]:
        """Determine the most likely geographic location."""
        locations = []
        
        for indicator in indicators:
            if indicator.geolocation:
                locations.append(indicator.geolocation)
        
        if not locations:
            return None, Confidence.VERY_LOW
        
        # Count occurrences of each country
        country_counts = Counter()
        city_counts = Counter()
        
        for loc in locations:
            if loc.country:
                country_counts[loc.country] += 1
            if loc.city:
                city_counts[loc.city] += 1
        
        # Get most common country and city
        most_common_country = country_counts.most_common(1)[0] if country_counts else (None, 0)
        most_common_city = city_counts.most_common(1)[0] if city_counts else (None, 0)
        
        # Find a location with the most common country
        consensus_location = None
        for loc in locations:
            if loc.country == most_common_country[0]:
                consensus_location = loc
                break
        
        # Determine confidence based on agreement
        total_sources = len(locations)
        country_agreement = most_common_country[1] / total_sources if total_sources > 0 else 0
        
        confidence = Confidence.LOW
        if country_agreement >= 0.8:
            confidence = Confidence.HIGH
        elif country_agreement >= 0.6:
            confidence = Confidence.MEDIUM
        
        return consensus_location, confidence
    
    def _determine_primary_network(self, indicators: List[NormalizedIndicator]) -> Optional[NetworkData]:
        """Determine primary network information."""
        networks = [ind.network for ind in indicators if ind.network]
        
        if not networks:
            return None
        
        # Count ASN occurrences
        asn_counts = Counter()
        org_counts = Counter()
        
        for net in networks:
            if net.asn:
                asn_counts[net.asn] += 1
            if net.organization:
                org_counts[net.organization] += 1
        
        # Create consensus network info
        primary_asn = asn_counts.most_common(1)[0][0] if asn_counts else None
        primary_org = org_counts.most_common(1)[0][0] if org_counts else None
        
        # Find network with primary ASN
        for net in networks:
            if net.asn == primary_asn:
                return net
        
        # Fallback to first available network
        return networks[0]
    
    def _aggregate_threat_intelligence(self, indicators: List[NormalizedIndicator]) -> Optional[ThreatIntelligence]:
        """Aggregate threat intelligence from all sources."""
        all_malware_families = set()
        all_attack_types = set()
        all_iocs = set()
        all_ttps = set()
        all_threat_actors = set()
        all_campaigns = set()
        
        for indicator in indicators:
            if indicator.threat_intelligence:
                ti = indicator.threat_intelligence
                all_malware_families.update(ti.malware_families)
                all_attack_types.update(ti.attack_types)
                all_iocs.update(ti.iocs)
                all_ttps.update(ti.ttps)
                all_threat_actors.update(ti.threat_actors)
                all_campaigns.update(ti.campaigns)
        
        if not any([all_malware_families, all_attack_types, all_iocs, all_ttps, all_threat_actors, all_campaigns]):
            return None
        
        return ThreatIntelligence(
            malware_families=list(all_malware_families),
            attack_types=list(all_attack_types),
            iocs=list(all_iocs),
            ttps=list(all_ttps),
            threat_actors=list(all_threat_actors),
            campaigns=list(all_campaigns)
        )
    
    def _count_threat_votes(self, indicators: List[NormalizedIndicator]) -> Dict[str, int]:
        """Count threat level votes from sources."""
        votes = {'malicious': 0, 'benign': 0, 'suspicious': 0, 'unknown': 0}
        
        for indicator in indicators:
            if indicator.threat_intelligence:
                threat_level = indicator.threat_intelligence.threat_level
                if threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL]:
                    votes['malicious'] += 1
                elif threat_level == ThreatLevel.BENIGN:
                    votes['benign'] += 1
                elif threat_level == ThreatLevel.SUSPICIOUS:
                    votes['suspicious'] += 1
                else:
                    votes['unknown'] += 1
        
        return votes
    
    def _identify_conflicts(self, indicators: List[NormalizedIndicator]) -> List[str]:
        """Identify conflicting data between sources."""
        conflicts = []
        
        # Check for threat level conflicts
        threat_levels = set()
        for indicator in indicators:
            if indicator.threat_intelligence:
                threat_levels.add(indicator.threat_intelligence.threat_level)
        
        if len(threat_levels) > 2:  # Allow some disagreement
            conflicts.append(f"Conflicting threat assessments: {', '.join(threat_levels)}")
        
        # Check for location conflicts
        countries = set()
        for indicator in indicators:
            if indicator.geolocation and indicator.geolocation.country:
                countries.add(indicator.geolocation.country)
        
        if len(countries) > 1:
            conflicts.append(f"Conflicting geographic locations: {', '.join(countries)}")
        
        # Check for ASN conflicts
        asns = set()
        for indicator in indicators:
            if indicator.network and indicator.network.asn:
                asns.add(str(indicator.network.asn))
        
        if len(asns) > 1:
            conflicts.append(f"Conflicting ASN information: {', '.join(asns)}")
        
        return conflicts
    
    def _generate_analysis_notes(self, indicators: List[NormalizedIndicator], votes: Dict[str, int]) -> List[str]:
        """Generate analysis notes based on aggregated data."""
        notes = []
        
        # Source coverage note
        sources = [ind.sources[0].name for ind in indicators if ind.sources]
        notes.append(f"Data collected from {len(sources)} sources: {', '.join(set(sources))}")
        
        # Threat assessment note
        if votes['malicious'] > votes['benign']:
            notes.append(f"Majority assessment: THREAT ({votes['malicious']} malicious vs {votes['benign']} benign votes)")
        elif votes['benign'] > votes['malicious']:
            notes.append(f"Majority assessment: BENIGN ({votes['benign']} benign vs {votes['malicious']} malicious votes)")
        else:
            notes.append(f"Mixed assessment: {votes['malicious']} malicious, {votes['benign']} benign, {votes['suspicious']} suspicious")
        
        # Data freshness note
        latest_data = max((ind.last_seen for ind in indicators if ind.last_seen), default=None)
        if latest_data:
            age_days = (datetime.utcnow() - latest_data).days
            if age_days == 0:
                notes.append("Data is current (collected today)")
            elif age_days == 1:
                notes.append("Data is recent (collected yesterday)")
            else:
                notes.append(f"Data age: {age_days} days old")
        
        return notes


def process_normalized_files(input_dir: Path, output_dir: Path) -> ProcessingStats:
    """Process all normalized files and create aggregated data."""
    aggregator = DataAggregator()
    stats = ProcessingStats()
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Collect all normalized indicators
    all_indicators = []
    
    # Process each source directory
    for source_dir in input_dir.iterdir():
        if not source_dir.is_dir():
            continue
        
        source_name = source_dir.name
        logger.info(f"Loading normalized data from {source_name}...")
        stats.sources_processed.append(source_name)
        
        # Load all normalized files from this source
        for jsonl_file in source_dir.glob('normalized_*.jsonl'):
            try:
                with open(jsonl_file, 'r', encoding='utf-8') as infile:
                    for line in infile:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            data = json.loads(line)
                            indicator = NormalizedIndicator(**data)
                            all_indicators.append(indicator)
                            stats.total_normalized_records += 1
                        except Exception as e:
                            logger.error(f"Error loading normalized record: {e}")
                            stats.errors.append(f"Error in {jsonl_file}: {str(e)}")
                            
            except Exception as e:
                logger.error(f"Error reading file {jsonl_file}: {e}")
                stats.errors.append(f"Error reading {jsonl_file}: {str(e)}")
    
    logger.info(f"Loaded {len(all_indicators)} normalized indicators")
    
    # Aggregate indicators
    logger.info("Aggregating indicators...")
    aggregated_indicators = aggregator.aggregate_indicators(all_indicators)
    stats.total_aggregated_records = len(aggregated_indicators)
    
    # Save aggregated data
    output_file = output_dir / f"aggregated_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for aggregated in aggregated_indicators:
            outfile.write(aggregated.model_dump_json() + '\n')
    
    # Create summary report
    summary_file = output_dir / f"summary_{datetime.now().strftime('%Y-%m-%d')}.json"
    
    # Generate summary statistics
    threat_distribution = Counter()
    source_coverage = Counter()
    
    for agg in aggregated_indicators:
        threat_distribution[agg.consensus_threat_level] += 1
        source_coverage[agg.total_sources] += 1
    
    summary = {
        'processing_stats': stats.model_dump(),
        'threat_distribution': dict(threat_distribution),
        'source_coverage': dict(source_coverage),
        'total_unique_indicators': len(aggregated_indicators),
        'high_confidence_threats': len([a for a in aggregated_indicators 
                                       if a.consensus_threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL]
                                       and a.consensus_confidence in [Confidence.HIGH, Confidence.VERY_HIGH]]),
        'multi_source_indicators': len([a for a in aggregated_indicators if a.total_sources > 1])
    }
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, default=str)
    
    stats.processing_end_time = datetime.utcnow()
    logger.info(f"Aggregation complete. Processed {stats.total_aggregated_records} unique indicators")
    
    return stats