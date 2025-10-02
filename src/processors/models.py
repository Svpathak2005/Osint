"""
Data models for normalized OSINT data.
Provides common schemas for different types of indicators and their attributes.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
from enum import Enum


class IndicatorType(str, Enum):
    """Types of indicators supported by the system."""
    IPV4 = "ipv4"
    IPV6 = "ipv6" 
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILE = "file"


class ThreatLevel(str, Enum):
    """Threat level classification."""
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious" 
    MALICIOUS = "malicious"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence levels for assessments."""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class GeolocationData(BaseModel):
    """Geographic location information."""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    region_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    continent: Optional[str] = None


class NetworkData(BaseModel):
    """Network-related information."""
    asn: Optional[int] = None
    asn_name: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    network_range: Optional[str] = None
    reverse_dns: Optional[List[str]] = Field(default_factory=list)
    domains: Optional[List[str]] = Field(default_factory=list)


class ThreatIntelligence(BaseModel):
    """Threat intelligence assessment."""
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: Confidence = Confidence.MEDIUM
    malware_families: List[str] = Field(default_factory=list)
    attack_types: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)  # Indicators of Compromise
    ttps: List[str] = Field(default_factory=list)  # Tactics, Techniques, Procedures
    threat_actors: List[str] = Field(default_factory=list)
    campaigns: List[str] = Field(default_factory=list)


class ReputationScore(BaseModel):
    """Reputation scoring from various sources."""
    source: str
    score: float  # Normalized 0-100 (0=benign, 100=malicious)
    max_score: float
    category: str
    last_updated: datetime


class PortInfo(BaseModel):
    """Information about open ports."""
    port: int
    protocol: str  # tcp/udp
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    ssl_info: Optional[Dict[str, Any]] = None


class VulnerabilityInfo(BaseModel):
    """Vulnerability information."""
    cve_id: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    description: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class SourceData(BaseModel):
    """Information about the data source."""
    name: str
    fetched_at: datetime
    confidence: Confidence = Confidence.MEDIUM
    raw_data: Optional[Dict[str, Any]] = None


class NormalizedIndicator(BaseModel):
    """Normalized indicator data structure."""
    # Core identification
    indicator: str
    indicator_type: IndicatorType
    
    # Geographic and network data
    geolocation: Optional[GeolocationData] = None
    network: Optional[NetworkData] = None
    
    # Threat intelligence
    threat_intelligence: Optional[ThreatIntelligence] = None
    reputation_scores: List[ReputationScore] = Field(default_factory=list)
    
    # Technical details
    ports: List[PortInfo] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = Field(default_factory=list)
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    sources: List[SourceData] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Additional attributes for different indicator types
    additional_data: Dict[str, Any] = Field(default_factory=dict)


class AggregatedIndicator(BaseModel):
    """Aggregated data from multiple sources for a single indicator."""
    indicator: str
    indicator_type: IndicatorType
    
    # Consensus data
    consensus_threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    consensus_confidence: Confidence = Confidence.MEDIUM
    overall_reputation_score: float = 0.0  # 0-100 scale
    
    # Geographic consensus
    most_likely_location: Optional[GeolocationData] = None
    location_confidence: Confidence = Confidence.MEDIUM
    
    # Network consensus  
    primary_network: Optional[NetworkData] = None
    
    # Aggregated threat intelligence
    aggregated_threats: Optional[ThreatIntelligence] = None
    
    # Source statistics
    total_sources: int = 0
    malicious_votes: int = 0
    benign_votes: int = 0
    suspicious_votes: int = 0
    
    # Time tracking
    first_seen: Optional[datetime] = None
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    
    # All source data
    normalized_sources: List[NormalizedIndicator] = Field(default_factory=list)
    
    # Analysis metadata
    analysis_notes: List[str] = Field(default_factory=list)
    conflicting_data: List[str] = Field(default_factory=list)


class ProcessingStats(BaseModel):
    """Statistics about data processing."""
    total_raw_records: int = 0
    total_normalized_records: int = 0
    total_aggregated_records: int = 0
    processing_start_time: datetime = Field(default_factory=datetime.utcnow)
    processing_end_time: Optional[datetime] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    sources_processed: List[str] = Field(default_factory=list)