# OSINT Data Collection and Analysis Platform

A comprehensive Open Source Intelligence (OSINT) platform for collecting, normalizing, aggregating, and analyzing threat intelligence data from multiple sources.

## 🎯 Features

### Data Collection
- **Multi-Source Integration**: Collect data from 8+ threat intelligence sources
  - Shodan (Internet-connected devices)
  - VirusTotal (File/URL/IP analysis)
  - AbuseIPDB (IP reputation)
  - AlienVault OTX (Threat pulses)
  - GreyNoise (Internet noise analysis)
  - Censys (Internet-wide scanning)
  - URLhaus (Malware URLs)
  - MalwareBazaar (Malware samples)

### Data Processing
- **Normalization**: Convert raw API responses into standardized format
- **Aggregation**: Combine data from multiple sources for comprehensive analysis
- **Deduplication**: Eliminate duplicate indicators across sources
- **Enrichment**: Add geolocation, network, and threat intelligence context

### Analysis & Reporting
- **Threat Intelligence Reports**: Comprehensive analysis with executive summaries
- **IOC Feeds**: Machine-readable indicators for security tools
- **Summary Dashboards**: Key metrics and visualizations
- **Geographic Analysis**: Location-based threat patterns
- **Network Analysis**: ASN and organization-based insights

## 🚀 Quick Start

### 1. Installation
```bash
git clone <your-repo-url>
cd Osint
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac

pip install -r requirements.txt
```

### 2. Configuration
```bash
# Copy example configuration
copy config\config.yaml.example config\config.yaml

# Create environment file for API keys
echo "# API Keys" > .env
echo "SHODAN_API_KEY=your_shodan_key" >> .env
echo "VIRUSTOTAL_API_KEY=your_vt_key" >> .env
echo "ABUSEIPDB_API_KEY=your_abuse_key" >> .env
# ... add other API keys
```

### 3. Demo Run
```bash
# Run the demo with sample data
python demo.py
```

### 4. Collect Real Data
```bash
# Run all collectors
python src/collectors/run_all.py

# Or run specific collector
python src/collectors/shodan.py
```

### 5. Process Data
```bash
# Run complete pipeline (normalize + aggregate + report)
python src/process_data.py pipeline

# Or run individual steps
python src/process_data.py normalize
python src/process_data.py aggregate
python src/process_data.py report
```

## 📊 Data Pipeline

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Raw Data      │───▶│   Normalized     │───▶│   Aggregated    │
│   (API Sources) │    │   (Standardized) │    │   (Combined)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                       │
         ▼                        ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  data/raw/      │    │  data/normalized/│    │ data/aggregated/│
│  ├── shodan/    │    │  ├── shodan/     │    │ ├── *.jsonl     │
│  ├── vt/        │    │  ├── vt/         │    │ └── summary.json│
│  └── ...        │    │  └── ...         │    └─────────────────┘
└─────────────────┘    └──────────────────┘             │
                                                        ▼
                                               ┌─────────────────┐
                                               │    Reports      │
                                               │  ├── threat_*   │
                                               │  ├── ioc_*      │
                                               │  └── dashboard_*│
                                               └─────────────────┘
```

## 🔧 CLI Usage

### Data Processing Commands

```bash
# Normalize raw data from all sources
python src/process_data.py normalize

# Normalize specific source only
python src/process_data.py normalize --source shodan

# Aggregate normalized data
python src/process_data.py aggregate

# Run full pipeline
python src/process_data.py pipeline

# Generate reports
python src/process_data.py report

# Generate specific report type
python src/process_data.py report --report-type ioc --min-confidence high

# Check data status
python src/process_data.py status
```

### Data Collection Commands

```bash
# Run all collectors
python src/collectors/run_all.py

# Run specific collector
python src/collectors/shodan.py --target 192.168.1.0/24
python src/collectors/virustotal.py --target malicious.example.com
```

## 📁 Project Structure

```
Osint/
├── src/
│   ├── collectors/           # Data collection modules
│   │   ├── shodan.py
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── otx.py
│   │   ├── greynoise.py
│   │   ├── censys.py
│   │   ├── urlhaus.py
│   │   ├── malwarebazaar.py
│   │   └── run_all.py
│   ├── processors/           # Data processing modules
│   │   ├── models.py         # Data models
│   │   ├── normalizer.py     # Data normalization
│   │   ├── aggregator.py     # Data aggregation
│   │   └── reporter.py       # Report generation
│   └── process_data.py       # CLI interface
├── data/
│   ├── raw/                  # Raw API responses
│   ├── normalized/           # Standardized data
│   └── aggregated/           # Combined analysis
├── reports/                  # Generated reports
├── config/
│   └── config.yaml          # Configuration
├── requirements.txt
├── demo.py                  # Demo script
└── README.md
```

## 🔍 Data Models

### Normalized Indicator
```python
{
    "indicator": "192.168.1.100",
    "indicator_type": "ip_address",
    "sources": [{"name": "shodan", "confidence": "high"}],
    "reputation_scores": [{"source": "shodan", "score": 85, "max_score": 100}],
    "threat_intelligence": {
        "threat_level": "suspicious",
        "confidence": "medium",
        "malware_families": ["Zeus"],
        "attack_types": ["botnet"]
    },
    "geolocation": {
        "country": "United States",
        "city": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060
    },
    "network": {
        "asn": 12345,
        "organization": "Example ISP",
        "isp": "Example Internet Provider"
    },
    "first_seen": "2025-01-01T10:00:00Z",
    "last_seen": "2025-01-02T10:00:00Z"
}
```

### Aggregated Indicator
```python
{
    "indicator": "192.168.1.100",
    "indicator_type": "ip_address",
    "consensus_threat_level": "malicious",
    "consensus_confidence": "high",
    "overall_reputation_score": 75.5,
    "total_sources": 3,
    "malicious_votes": 2,
    "benign_votes": 1,
    "suspicious_votes": 0,
    "most_likely_location": {...},
    "primary_network": {...},
    "aggregated_threats": {...},
    "analysis_notes": [
        "Data collected from 3 sources: shodan, virustotal, abuseipdb",
        "Majority assessment: THREAT (2 malicious vs 1 benign votes)"
    ],
    "conflicting_data": []
}
```

## 📈 Report Types

### 1. Threat Intelligence Report
Comprehensive analysis including:
- Executive summary with key findings
- Threat landscape analysis
- Geographic distribution
- Network analysis
- High-priority indicators
- Actionable recommendations

### 2. IOC Feed
Machine-readable indicators for security tools:
- High-confidence malicious indicators
- STIX/TAXII compatible format
- Confidence scores and metadata
- Tags and classifications

### 3. Summary Dashboard
Key metrics and visualizations:
- Threat distribution charts
- Source coverage statistics
- Geographic heat maps
- Temporal analysis
- Data quality metrics

## ⚙️ Configuration

### API Keys (.env file)
```bash
# Threat Intelligence APIs
SHODAN_API_KEY=your_shodan_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key
GREYNOISE_API_KEY=your_greynoise_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
```

### Configuration (config/config.yaml)
```yaml
data_collection:
  rate_limiting:
    shodan: 1.0    # requests per second
    virustotal: 4.0
    abuseipdb: 10.0
  
  batch_sizes:
    default: 100
    virustotal: 25
  
  timeout: 30

data_processing:
  normalization:
    strict_validation: true
    include_raw_data: false
  
  aggregation:
    min_sources: 1
    confidence_threshold: 0.5
  
  reporting:
    include_source_details: true
    max_indicators_per_report: 10000

logging:
  level: INFO
  file: osint.log
```

## 🔒 Security Considerations

### API Key Protection
- Store API keys in `.env` file (never commit to git)
- Use environment variables in production
- Rotate keys regularly
- Monitor API usage and limits

### Data Handling
- Raw data may contain sensitive information
- Ensure proper data retention policies
- Consider data encryption at rest
- Implement access controls for reports

### Rate Limiting
- Respect API rate limits
- Implement exponential backoff
- Monitor API quotas
- Use caching where appropriate

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
python -m pytest tests/

# Run specific test
python -m pytest tests/test_normalizer.py

# Run with coverage
python -m pytest --cov=src tests/
```

### Integration Tests
```bash
# Test with sample data
python demo.py

# Test specific collectors (requires API keys)
python src/collectors/shodan.py --test
```

## 📊 Performance

### Optimization Tips
1. **Parallel Processing**: Use multiple threads for data collection
2. **Caching**: Cache API responses to reduce redundant calls
3. **Batch Processing**: Group multiple indicators in single requests
4. **Rate Limiting**: Optimize request rates for each API
5. **Data Compression**: Compress stored data to save space

### Monitoring
- Monitor API usage and quotas
- Track processing times and errors
- Monitor data quality metrics
- Set up alerts for critical issues

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

### Adding New Data Sources
1. Create collector in `src/collectors/`
2. Add normalization logic in `src/processors/normalizer.py`
3. Update data models if needed
4. Add configuration options
5. Include tests and documentation

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Check this README and code comments
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately

## 🙏 Acknowledgments

- Thanks to all threat intelligence providers
- Inspired by open source security tools
- Built with Python and modern libraries
- Community contributions welcome

---

**⚠️ Disclaimer**: This tool is for legitimate security research and threat hunting only. Users are responsible for complying with all applicable laws and API terms of service.
