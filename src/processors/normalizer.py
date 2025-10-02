"""
Data normalization engine for OSINT sources.
Converts raw API responses into standardized format.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from ipaddress import AddressValueError, ip_address

from .models import (
    NormalizedIndicator, IndicatorType, GeolocationData, NetworkData,
    ThreatIntelligence, ThreatLevel, Confidence, ReputationScore,
    PortInfo, VulnerabilityInfo, SourceData
)

logger = logging.getLogger(__name__)


class DataNormalizer:
    """Normalizes data from different OSINT sources into a common format."""
    
    def __init__(self):
        self.source_normalizers = {
            'shodan': self._normalize_shodan,
            'virustotal': self._normalize_virustotal,
            'abuseipdb': self._normalize_abuseipdb,
            'otx': self._normalize_otx,
            'greynoise': self._normalize_greynoise,
            'censys': self._normalize_censys,
            'urlhaus': self._normalize_urlhaus,
            'malwarebazaar': self._normalize_malwarebazaar
        }
    
    def normalize_record(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize a single raw record."""
        try:
            source = raw_record.get('source', '').lower()
            indicator = raw_record.get('indicator', '')
            indicator_type = self._determine_indicator_type(indicator)
            
            if source not in self.source_normalizers:
                logger.warning(f"No normalizer found for source: {source}")
                return None
            
            # Use source-specific normalizer
            normalizer = self.source_normalizers[source]
            normalized = normalizer(raw_record)
            
            if normalized:
                normalized.indicator_type = indicator_type
                
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing record: {e}")
            return None
    
    def _determine_indicator_type(self, indicator: str) -> IndicatorType:
        """Determine the type of indicator."""
        try:
            # Try to parse as IP address
            ip_addr = ip_address(indicator)
            return IndicatorType.IPV4 if ip_addr.version == 4 else IndicatorType.IPV6
        except AddressValueError:
            pass
        
        # Check for hash patterns
        if len(indicator) == 32 and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return IndicatorType.HASH_MD5
        elif len(indicator) == 40 and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return IndicatorType.HASH_SHA1
        elif len(indicator) == 64 and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return IndicatorType.HASH_SHA256
        
        # Check for email pattern
        if '@' in indicator and '.' in indicator:
            return IndicatorType.EMAIL
        
        # Check for URL pattern
        if indicator.startswith(('http://', 'https://', 'ftp://')):
            return IndicatorType.URL
        
        # Default to domain
        return IndicatorType.DOMAIN
    
    def _normalize_shodan(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize Shodan data."""
        try:
            data = raw_record.get('data', {})
            indicator = raw_record.get('indicator', '')
            
            # Extract geolocation
            location_data = data.get('location', {}) or {}
            if not location_data and data.get('data'):
                # Check if location is in the first service record
                first_record = data.get('data', [{}])[0] if data.get('data') else {}
                location_data = first_record.get('location', {})
            
            geolocation = GeolocationData(
                country=location_data.get('country_name'),
                country_code=location_data.get('country_code'),
                region=location_data.get('region_code'),
                city=location_data.get('city'),
                latitude=location_data.get('latitude'),
                longitude=location_data.get('longitude')
            )
            
            # Extract network information
            network = NetworkData(
                asn=int(data.get('asn', '').replace('AS', '')) if data.get('asn') else None,
                organization=data.get('org'),
                isp=data.get('isp'),
                reverse_dns=data.get('hostnames', []),
                domains=data.get('domains', [])
            )
            
            # Extract port information
            ports = []
            if data.get('ports'):
                for port in data.get('ports', []):
                    ports.append(PortInfo(port=port, protocol='tcp'))
            
            # Extract from service data
            for service in data.get('data', []):
                port_info = PortInfo(
                    port=service.get('port'),
                    protocol=service.get('transport', 'tcp'),
                    service=service.get('product'),
                    version=service.get('version'),
                    banner=service.get('data')
                )
                
                # Add SSL information if available
                if service.get('ssl'):
                    port_info.ssl_info = {
                        'cert_subject': service['ssl'].get('cert', {}).get('subject'),
                        'cert_issuer': service['ssl'].get('cert', {}).get('issuer'),
                        'cipher': service['ssl'].get('cipher', {}).get('name'),
                        'versions': service['ssl'].get('versions', [])
                    }
                
                ports.append(port_info)
            
            # Extract vulnerabilities
            vulnerabilities = []
            for service in data.get('data', []):
                vulns = service.get('opts', {}).get('vulns', [])
                for vuln in vulns:
                    vulnerabilities.append(VulnerabilityInfo(
                        cve_id=vuln,
                        description=f"Vulnerability found in service on port {service.get('port')}"
                    ))
            
            # Create source data
            source_data = SourceData(
                name='shodan',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00')),
                confidence=Confidence.HIGH,
                raw_data=data
            )
            
            # Create tags
            tags = data.get('tags', [])
            if data.get('org'):
                tags.append(f"org:{data['org']}")
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.IPV4,  # Will be overridden
                geolocation=geolocation,
                network=network,
                ports=ports,
                vulnerabilities=vulnerabilities,
                tags=tags,
                sources=[source_data],
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing Shodan data: {e}")
            return None
    
    def _normalize_virustotal(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize VirusTotal data."""
        try:
            data = raw_record.get('data', {}).get('data', {})
            attributes = data.get('attributes', {})
            indicator = raw_record.get('indicator', '')
            
            # Extract reputation scores
            reputation_scores = []
            last_analysis_results = attributes.get('last_analysis_results', {})
            
            for engine, result in last_analysis_results.items():
                category = result.get('category', 'undetected')
                score = 0
                if category == 'malicious':
                    score = 100
                elif category == 'suspicious':
                    score = 75
                elif category == 'harmless':
                    score = 0
                else:  # undetected
                    score = 50
                
                reputation_scores.append(ReputationScore(
                    source=f"virustotal_{engine}",
                    score=score,
                    max_score=100,
                    category=category,
                    last_updated=datetime.fromtimestamp(attributes.get('last_analysis_date', 0))
                ))
            
            # Determine overall threat level
            stats = attributes.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total_engines = sum(stats.values()) if stats else 1
            
            threat_level = ThreatLevel.UNKNOWN
            if malicious_count > 0:
                threat_level = ThreatLevel.MALICIOUS
            elif suspicious_count > 0:
                threat_level = ThreatLevel.SUSPICIOUS
            elif stats.get('harmless', 0) > 0:
                threat_level = ThreatLevel.BENIGN
            
            # Create threat intelligence
            threat_intel = ThreatIntelligence(
                threat_level=threat_level,
                confidence=Confidence.HIGH if total_engines > 10 else Confidence.MEDIUM
            )
            
            # Extract network information for IP addresses
            network = None
            if raw_record.get('type') == 'ipv4':
                network = NetworkData(
                    asn=attributes.get('asn'),
                    organization=attributes.get('as_owner'),
                    network_range=attributes.get('network')
                )
            
            # Create source data
            source_data = SourceData(
                name='virustotal',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('+00:00', 'Z').replace('Z', '+00:00')),
                confidence=Confidence.HIGH,
                raw_data=data
            )
            
            # Create tags
            tags = ['virustotal']
            if attributes.get('country'):
                tags.append(f"country:{attributes['country']}")
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.IPV4,  # Will be overridden
                network=network,
                threat_intelligence=threat_intel,
                reputation_scores=reputation_scores,
                tags=tags,
                sources=[source_data],
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing VirusTotal data: {e}")
            return None
    
    def _normalize_abuseipdb(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize AbuseIPDB data."""
        try:
            data = raw_record.get('data', {}).get('data', {})
            indicator = raw_record.get('indicator', '')
            
            # Extract reputation score
            confidence_percentage = data.get('abuseConfidencePercentage', 0)
            reputation_scores = [ReputationScore(
                source='abuseipdb',
                score=confidence_percentage,
                max_score=100,
                category='malicious' if confidence_percentage > 50 else 'harmless',
                last_updated=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00'))
            )]
            
            # Determine threat level
            threat_level = ThreatLevel.BENIGN
            if confidence_percentage > 75:
                threat_level = ThreatLevel.MALICIOUS
            elif confidence_percentage > 25:
                threat_level = ThreatLevel.SUSPICIOUS
            
            # Create threat intelligence
            threat_intel = ThreatIntelligence(
                threat_level=threat_level,
                confidence=Confidence.HIGH if data.get('totalReports', 0) > 5 else Confidence.MEDIUM,
                attack_types=[cat for cat in data.get('usageType', '').split(',') if cat.strip()]
            )
            
            # Extract geolocation
            geolocation = GeolocationData(
                country=data.get('countryName'),
                country_code=data.get('countryCode')
            )
            
            # Extract network information
            network = NetworkData(
                organization=data.get('isp'),
                isp=data.get('isp')
            )
            
            # Create source data
            source_data = SourceData(
                name='abuseipdb',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00')),
                confidence=Confidence.HIGH,
                raw_data=data
            )
            
            # Create tags
            tags = ['abuseipdb']
            if data.get('isWhitelisted'):
                tags.append('whitelisted')
            if data.get('usageType'):
                tags.extend([f"usage:{usage.strip()}" for usage in data['usageType'].split(',')])
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.IPV4,  # Will be overridden
                geolocation=geolocation,
                network=network,
                threat_intelligence=threat_intel,
                reputation_scores=reputation_scores,
                tags=tags,
                sources=[source_data],
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing AbuseIPDB data: {e}")
            return None
    
    def _normalize_otx(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize AlienVault OTX data."""
        try:
            # OTX implementation - simplified for now
            data = raw_record.get('data', {})
            indicator = raw_record.get('indicator', '')
            
            source_data = SourceData(
                name='otx',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00')),
                confidence=Confidence.MEDIUM,
                raw_data=data
            )
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.IPV4,  # Will be overridden
                sources=[source_data],
                tags=['otx'],
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing OTX data: {e}")
            return None
    
    def _normalize_greynoise(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize GreyNoise data."""
        try:
            data = raw_record.get('data', {})
            indicator = raw_record.get('indicator', '')
            
            # Extract threat classification
            classification = data.get('classification', 'unknown')
            threat_level = ThreatLevel.UNKNOWN
            if classification == 'malicious':
                threat_level = ThreatLevel.MALICIOUS
            elif classification == 'benign':
                threat_level = ThreatLevel.BENIGN
            
            threat_intel = ThreatIntelligence(
                threat_level=threat_level,
                confidence=Confidence.HIGH,
                attack_types=data.get('tags', [])
            )
            
            # Extract geolocation
            geolocation = GeolocationData(
                country=data.get('metadata', {}).get('country'),
                country_code=data.get('metadata', {}).get('country_code'),
                city=data.get('metadata', {}).get('city'),
                organization=data.get('metadata', {}).get('organization')
            )
            
            source_data = SourceData(
                name='greynoise',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00')),
                confidence=Confidence.HIGH,
                raw_data=data
            )
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.IPV4,  # Will be overridden
                geolocation=geolocation,
                threat_intelligence=threat_intel,
                sources=[source_data],
                tags=['greynoise'] + data.get('tags', []),
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing GreyNoise data: {e}")
            return None
    
    def _normalize_censys(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize Censys data."""
        try:
            # Censys implementation - simplified for now
            data = raw_record.get('data', {})
            indicator = raw_record.get('indicator', '')
            
            source_data = SourceData(
                name='censys',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00')),
                confidence=Confidence.HIGH,
                raw_data=data
            )
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.IPV4,  # Will be overridden
                sources=[source_data],
                tags=['censys'],
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing Censys data: {e}")
            return None
    
    def _normalize_urlhaus(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize URLhaus data."""
        try:
            # URLhaus implementation - simplified for now
            data = raw_record.get('data', {})
            indicator = raw_record.get('indicator', '')
            
            source_data = SourceData(
                name='urlhaus',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00')),
                confidence=Confidence.HIGH,
                raw_data=data
            )
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.URL,  # Will be overridden
                sources=[source_data],
                tags=['urlhaus'],
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing URLhaus data: {e}")
            return None
    
    def _normalize_malwarebazaar(self, raw_record: Dict[str, Any]) -> Optional[NormalizedIndicator]:
        """Normalize MalwareBazaar data."""
        try:
            # MalwareBazaar implementation - simplified for now
            data = raw_record.get('data', {})
            indicator = raw_record.get('indicator', '')
            
            source_data = SourceData(
                name='malwarebazaar',
                fetched_at=datetime.fromisoformat(raw_record.get('fetched_at', '').replace('Z', '+00:00')),
                confidence=Confidence.HIGH,
                raw_data=data
            )
            
            return NormalizedIndicator(
                indicator=indicator,
                indicator_type=IndicatorType.HASH_SHA256,  # Will be overridden
                sources=[source_data],
                tags=['malwarebazaar'],
                last_seen=source_data.fetched_at
            )
            
        except Exception as e:
            logger.error(f"Error normalizing MalwareBazaar data: {e}")
            return None


def process_raw_files(input_dir: Path, output_dir: Path) -> Dict[str, int]:
    """Process all raw JSONL files and normalize them."""
    normalizer = DataNormalizer()
    stats = {'processed': 0, 'normalized': 0, 'errors': 0}
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Process each source directory
    for source_dir in input_dir.iterdir():
        if not source_dir.is_dir():
            continue
            
        source_name = source_dir.name
        logger.info(f"Processing {source_name} data...")
        
        # Create source-specific output directory
        source_output_dir = output_dir / source_name
        source_output_dir.mkdir(exist_ok=True)
        
        # Process all JSONL files in the source directory
        for jsonl_file in source_dir.glob('*.jsonl'):
            output_file = source_output_dir / f"normalized_{jsonl_file.name}"
            
            with open(jsonl_file, 'r', encoding='utf-8') as infile, \
                 open(output_file, 'w', encoding='utf-8') as outfile:
                
                for line in infile:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        raw_record = json.loads(line)
                        stats['processed'] += 1
                        
                        normalized = normalizer.normalize_record(raw_record)
                        if normalized:
                            outfile.write(normalized.model_dump_json() + '\n')
                            stats['normalized'] += 1
                        else:
                            stats['errors'] += 1
                            
                    except Exception as e:
                        logger.error(f"Error processing record in {jsonl_file}: {e}")
                        stats['errors'] += 1
    
    return stats