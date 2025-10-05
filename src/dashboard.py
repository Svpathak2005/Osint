"""
OSINT Dashboard - Interactive Data Visualization
Web-based dashboard for visualizing threat intelligence data from multiple sources.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.processors.models import AggregatedIndicator, ThreatLevel, Confidence


class OSINTDashboard:
    """Interactive OSINT data visualization dashboard."""
    
    def __init__(self):
        self.data_dir = Path('data')
        self.aggregated_dir = self.data_dir / 'aggregated'
        self.reports_dir = Path('reports')
        
        # Configure Streamlit page
        st.set_page_config(
            page_title="OSINT Threat Intelligence Dashboard",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Apply custom CSS
        self.apply_custom_css()
    
    def apply_custom_css(self):
        """Apply custom CSS styling to the dashboard."""
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .metric-card {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #2a5298;
            margin-bottom: 1rem;
        }
        
        .threat-critical {
            color: #dc3545 !important;
            font-weight: bold;
        }
        
        .threat-malicious {
            color: #fd7e14 !important;
            font-weight: bold;
        }
        
        .threat-suspicious {
            color: #ffc107 !important;
            font-weight: bold;
        }
        
        .threat-benign {
            color: #28a745 !important;
            font-weight: bold;
        }
        
        .sidebar .sidebar-content {
            background-color: #f8f9fa;
        }
        
        /* Fix all selectbox text visibility */
        .stSelectbox > div > div {
            background-color: white;
            color: #333333 !important;
        }
        
        .stSelectbox label {
            color: #ffffff !important;
            font-weight: 600;
        }
        
        .stSelectbox div[data-baseweb="select"] > div {
            color: #333333 !important;
        }
        
        /* Fix sidebar text elements */
        .css-1d391kg {
            color: #333333 !important;
        }
        
        /* Fix all sidebar labels and text */
        .sidebar .element-container label {
            color: #ffffff !important;
        }
        
        .sidebar .stMarkdown {
            color: #ffffff !important;
        }
        
        /* Fix slider labels */
        .stSlider label {
            color: #ffffff !important;
        }
        
        /* Fix date input labels */
        .stDateInput label {
            color: #ffffff !important;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def load_aggregated_data(self):
        """Load aggregated indicator data."""
        try:
            # Find latest aggregated file
            aggregated_files = list(self.aggregated_dir.glob('aggregated_*.jsonl'))
            if not aggregated_files:
                st.error("No aggregated data found. Please run the data processing pipeline first.")
                return []
            
            latest_file = max(aggregated_files, key=lambda f: f.stat().st_mtime)
            
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
                            logging.error(f"Error loading indicator: {e}")
            
            return indicators
            
        except Exception as e:
            st.error(f"Error loading data: {e}")
            return []
    
    def load_summary_data(self):
        """Load summary statistics data."""
        try:
            summary_files = list(self.aggregated_dir.glob('summary_*.json'))
            if not summary_files:
                return None
            
            latest_summary = max(summary_files, key=lambda f: f.stat().st_mtime)
            
            with open(latest_summary, 'r', encoding='utf-8-sig') as f:
                return json.load(f)
                
        except Exception as e:
            st.error(f"Error loading summary data: {e}")
            return None
    
    def create_indicators_dataframe(self, indicators):
        """Convert indicators to pandas DataFrame for easier analysis."""
        data = []
        
        for indicator in indicators:
            row = {
                'indicator': indicator.indicator,
                'type': indicator.indicator_type.value,
                'threat_level': indicator.consensus_threat_level.value,
                'confidence': indicator.consensus_confidence.value,
                'reputation_score': indicator.overall_reputation_score,
                'total_sources': indicator.total_sources,
                'malicious_votes': indicator.malicious_votes,
                'benign_votes': indicator.benign_votes,
                'suspicious_votes': indicator.suspicious_votes,
                'last_updated': indicator.last_updated,
                'country': indicator.most_likely_location.country if indicator.most_likely_location else None,
                'city': indicator.most_likely_location.city if indicator.most_likely_location else None,
                'asn': indicator.primary_network.asn if indicator.primary_network else None,
                'organization': indicator.primary_network.organization if indicator.primary_network else None,
            }
            
            # Add source information
            source_names = [source['name'] for source in indicator.all_sources] if indicator.all_sources else []
            row['sources'] = ','.join(source_names)  # Store as comma-separated string
            row['source_list'] = source_names  # Store as list for filtering
            
            # Add threat intelligence data
            if indicator.aggregated_threats:
                row['malware_families'] = len(indicator.aggregated_threats.malware_families)
                row['attack_types'] = len(indicator.aggregated_threats.attack_types)
                row['threat_actors'] = len(indicator.aggregated_threats.threat_actors)
            else:
                row['malware_families'] = 0
                row['attack_types'] = 0
                row['threat_actors'] = 0
            
            data.append(row)
        
        return pd.DataFrame(data)
    
    def render_header(self):
        """Render dashboard header."""
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ OSINT Threat Intelligence Dashboard</h1>
            <p>Interactive visualization of multi-source threat intelligence data</p>
        </div>
        """, unsafe_allow_html=True)
    
    def render_sidebar(self, df):
        """Render sidebar with filters and controls."""
        st.sidebar.title("🔧 Dashboard Controls")
        
        # Data refresh
        if st.sidebar.button("🔄 Refresh Data"):
            st.experimental_rerun()
        
        st.sidebar.markdown("---")
        
        # Filters
        st.sidebar.subheader("📊 Filters")
        
        # Threat level filter
        threat_levels = ['All'] + list(df['threat_level'].unique())
        selected_threat = st.sidebar.selectbox(
            "Threat Level",
            threat_levels,
            index=0
        )
        
        # Indicator type filter
        indicator_types = ['All'] + list(df['type'].unique())
        selected_type = st.sidebar.selectbox(
            "Indicator Type",
            indicator_types,
            index=0
        )
        
        # Confidence filter
        confidence_levels = ['All'] + list(df['confidence'].unique())
        selected_confidence = st.sidebar.selectbox(
            "Confidence Level",
            confidence_levels,
            index=0
        )
        
        # OSINT Source filter
        all_sources = set()
        for source_list in df['source_list']:
            if source_list:
                all_sources.update(source_list)
        
        source_options = ['All'] + sorted(list(all_sources))
        selected_source = st.sidebar.selectbox(
            "🔍 OSINT Source",
            source_options,
            index=0,
            help="Filter indicators by OSINT framework/source"
        )
        
        # Source count filter
        min_sources = st.sidebar.slider(
            "Minimum Sources",
            min_value=1,
            max_value=int(df['total_sources'].max()),
            value=1
        )
        
        # Date range filter
        date_range = None
        if not df['last_updated'].isna().all():
            df['last_updated'] = pd.to_datetime(df['last_updated'])
            data_min_date = df['last_updated'].min().date()
            data_max_date = df['last_updated'].max().date()
            
            # Provide a reasonable date range even if all data is from the same date
            if data_min_date == data_max_date:
                # Allow selection from 30 days before to 7 days after the data date
                range_start = data_min_date - timedelta(days=30)
                range_end = data_max_date + timedelta(days=7)
                default_start = data_min_date
                default_end = data_max_date
            else:
                # Use actual data range with some buffer
                range_start = data_min_date - timedelta(days=7)
                range_end = data_max_date + timedelta(days=7)
                default_start = data_min_date
                default_end = data_max_date
            
            date_range = st.sidebar.date_input(
                "Date Range",
                value=(default_start, default_end),
                min_value=range_start,
                max_value=range_end,
                help="Select date range to filter indicators by last updated date"
            )
        
        st.sidebar.markdown("---")
        
        # Export options
        st.sidebar.subheader("📥 Export Data")
        
        if st.sidebar.button("Export CSV"):
            csv = df.to_csv(index=False)
            st.sidebar.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"osint_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        # Apply filters
        filtered_df = df.copy()
        
        if selected_threat != 'All':
            filtered_df = filtered_df[filtered_df['threat_level'] == selected_threat]
        
        if selected_type != 'All':
            filtered_df = filtered_df[filtered_df['type'] == selected_type]
        
        if selected_confidence != 'All':
            filtered_df = filtered_df[filtered_df['confidence'] == selected_confidence]
        
        # Apply OSINT source filter
        if selected_source != 'All':
            filtered_df = filtered_df[filtered_df['source_list'].apply(
                lambda sources: selected_source in sources if sources else False
            )]
        
        filtered_df = filtered_df[filtered_df['total_sources'] >= min_sources]
        
        # Apply date range filter
        if date_range and len(date_range) == 2 and not filtered_df['last_updated'].isna().all():
            start_date, end_date = date_range
            filtered_df = filtered_df[
                (filtered_df['last_updated'].dt.date >= start_date) & 
                (filtered_df['last_updated'].dt.date <= end_date)
            ]
        
        return filtered_df
    
    def render_key_metrics(self, df, summary_data):
        """Render key metrics cards."""
        st.subheader("📊 Key Metrics")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                label="Total Indicators",
                value=len(df),
                delta=f"+{len(df)}" if len(df) > 0 else None
            )
        
        with col2:
            critical_count = len(df[df['threat_level'] == 'critical'])
            malicious_count = len(df[df['threat_level'] == 'malicious'])
            threats = critical_count + malicious_count
            st.metric(
                label="High Threats",
                value=threats,
                delta=f"{(threats/len(df)*100):.1f}%" if len(df) > 0 else "0%"
            )
        
        with col3:
            multi_source = len(df[df['total_sources'] > 1])
            st.metric(
                label="Multi-Source",
                value=multi_source,
                delta=f"{(multi_source/len(df)*100):.1f}%" if len(df) > 0 else "0%"
            )
        
        with col4:
            high_conf = len(df[df['confidence'].isin(['high', 'very_high'])])
            st.metric(
                label="High Confidence",
                value=high_conf,
                delta=f"{(high_conf/len(df)*100):.1f}%" if len(df) > 0 else "0%"
            )
        
        with col5:
            countries = df['country'].nunique()
            st.metric(
                label="Countries",
                value=countries,
                delta=None
            )
    
    def render_threat_distribution(self, df):
        """Render threat level distribution chart."""
        st.subheader("🎯 Threat Level Distribution")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Pie chart
            threat_counts = df['threat_level'].value_counts()
            
            colors = {
                'critical': '#dc3545',
                'malicious': '#fd7e14',
                'suspicious': '#ffc107',
                'unknown': '#6c757d',
                'benign': '#28a745'
            }
            
            fig = px.pie(
                values=threat_counts.values,
                names=threat_counts.index,
                title="Threat Level Distribution",
                color=threat_counts.index,
                color_discrete_map=colors
            )
            
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(showlegend=True, height=400)
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Threat level breakdown
            st.markdown("**Threat Breakdown:**")
            
            for threat_level in ['critical', 'malicious', 'suspicious', 'unknown', 'benign']:
                count = len(df[df['threat_level'] == threat_level])
                percentage = (count / len(df) * 100) if len(df) > 0 else 0
                
                color_class = f"threat-{threat_level}"
                st.markdown(
                    f'<div class="{color_class}">{threat_level.title()}: {count} ({percentage:.1f}%)</div>',
                    unsafe_allow_html=True
                )
    
    def render_confidence_analysis(self, df):
        """Render confidence level analysis."""
        st.subheader("🎯 Confidence Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Confidence vs Threat Level heatmap
            confidence_threat = pd.crosstab(df['confidence'], df['threat_level'])
            
            fig = px.imshow(
                confidence_threat.values,
                x=confidence_threat.columns,
                y=confidence_threat.index,
                title="Confidence vs Threat Level Heatmap",
                color_continuous_scale="Reds",
                text_auto=True
            )
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Source count vs confidence
            fig = px.scatter(
                df,
                x='total_sources',
                y='confidence',
                color='threat_level',
                size='reputation_score',
                title="Sources vs Confidence",
                hover_data=['indicator', 'type']
            )
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    def render_geographic_analysis(self, df):
        """Render geographic distribution analysis."""
        st.subheader("🌍 Geographic Analysis")
        
        # Filter out null countries
        geo_df = df[df['country'].notna()]
        
        if len(geo_df) == 0:
            st.warning("No geographic data available for visualization.")
            return
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Country distribution
            country_counts = geo_df['country'].value_counts().head(15)
            
            fig = px.bar(
                x=country_counts.values,
                y=country_counts.index,
                orientation='h',
                title="Top 15 Countries by Indicators",
                labels={'x': 'Number of Indicators', 'y': 'Country'}
            )
            
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Threat level by country
            country_threat = geo_df.groupby(['country', 'threat_level']).size().unstack(fill_value=0)
            country_threat = country_threat.head(10)
            
            fig = px.bar(
                country_threat,
                title="Threat Levels by Top 10 Countries",
                labels={'value': 'Number of Indicators', 'index': 'Country'}
            )
            
            fig.update_layout(height=500, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
    
    def render_temporal_analysis(self, df):
        """Render temporal analysis charts."""
        st.subheader("📅 Temporal Analysis")
        
        # Filter valid dates
        temporal_df = df[df['last_updated'].notna()].copy()
        
        if len(temporal_df) == 0:
            st.warning("No temporal data available for visualization.")
            return
        
        temporal_df['last_updated'] = pd.to_datetime(temporal_df['last_updated'])
        temporal_df['date'] = temporal_df['last_updated'].dt.date
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Daily indicator counts
            daily_counts = temporal_df.groupby('date').size().reset_index(name='count')
            
            fig = px.line(
                daily_counts,
                x='date',
                y='count',
                title="Daily Indicator Activity",
                labels={'count': 'Number of Indicators', 'date': 'Date'}
            )
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Threat level timeline
            threat_timeline = temporal_df.groupby(['date', 'threat_level']).size().unstack(fill_value=0)
            
            fig = px.area(
                threat_timeline,
                title="Threat Level Timeline",
                labels={'value': 'Number of Indicators', 'index': 'Date'}
            )
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    def render_source_analysis(self, df):
        """Render source coverage analysis."""
        st.subheader("🔍 Source Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Source count distribution
            source_dist = df['total_sources'].value_counts().sort_index()
            
            fig = px.bar(
                x=source_dist.index,
                y=source_dist.values,
                title="Source Count Distribution",
                labels={'x': 'Number of Sources', 'y': 'Number of Indicators'}
            )
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Voting patterns
            voting_data = df[['malicious_votes', 'benign_votes', 'suspicious_votes']].sum()
            
            fig = px.bar(
                x=voting_data.index,
                y=voting_data.values,
                title="Source Voting Patterns",
                labels={'x': 'Vote Type', 'y': 'Total Votes'},
                color=voting_data.index,
                color_discrete_map={
                    'malicious_votes': '#dc3545',
                    'benign_votes': '#28a745',
                    'suspicious_votes': '#ffc107'
                }
            )
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    def render_network_analysis(self, df):
        """Render network infrastructure analysis."""
        st.subheader("🌐 Network Analysis")
        
        # Filter non-null ASN data
        network_df = df[df['asn'].notna()]
        
        if len(network_df) == 0:
            st.warning("No network data available for visualization.")
            return
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Top ASNs
            asn_counts = network_df['asn'].value_counts().head(10)
            
            fig = px.bar(
                x=asn_counts.values,
                y=[f"AS{asn}" for asn in asn_counts.index],
                orientation='h',
                title="Top 10 ASNs by Indicators",
                labels={'x': 'Number of Indicators', 'y': 'ASN'}
            )
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Top Organizations
            org_df = network_df[network_df['organization'].notna()]
            if len(org_df) > 0:
                org_counts = org_df['organization'].value_counts().head(10)
                
                fig = px.bar(
                    x=org_counts.values,
                    y=org_counts.index,
                    orientation='h',
                    title="Top 10 Organizations by Indicators",
                    labels={'x': 'Number of Indicators', 'y': 'Organization'}
                )
                
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No organization data available.")
    
    def render_indicator_details(self, df):
        """Render detailed indicator table."""
        st.subheader("🔍 Indicator Details")
        
        # Create display DataFrame
        display_df = df[[
            'indicator', 'type', 'threat_level', 'confidence',
            'reputation_score', 'total_sources', 'country', 'organization'
        ]].copy()
        
        # Format reputation score
        display_df['reputation_score'] = display_df['reputation_score'].round(2)
        
        # Color-code threat levels
        def color_threat_level(val):
            colors = {
                'critical': 'background-color: #dc3545; color: white',
                'malicious': 'background-color: #fd7e14; color: white',
                'suspicious': 'background-color: #ffc107; color: black',
                'unknown': 'background-color: #6c757d; color: white',
                'benign': 'background-color: #28a745; color: white'
            }
            return colors.get(val, '')
        
        styled_df = display_df.style.applymap(color_threat_level, subset=['threat_level'])
        
        st.dataframe(styled_df, use_container_width=True, height=400)
        
        # Summary statistics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Average Reputation Score", f"{df['reputation_score'].mean():.2f}")
        
        with col2:
            st.metric("Average Sources per Indicator", f"{df['total_sources'].mean():.1f}")
        
        with col3:
            st.metric("Unique Countries", df['country'].nunique())
    
    def render_dashboard(self):
        """Render the complete dashboard."""
        # Header
        self.render_header()
        
        # Load data
        with st.spinner("Loading OSINT data..."):
            indicators = self.load_aggregated_data()
            summary_data = self.load_summary_data()
        
        if not indicators:
            st.error("No data available. Please run the data processing pipeline first.")
            st.info("Run: `python src/process_data.py pipeline` to generate data.")
            return
        
        # Convert to DataFrame
        df = self.create_indicators_dataframe(indicators)
        
        # Sidebar with filters
        filtered_df = self.render_sidebar(df)
        
        # Main dashboard content
        st.markdown(f"**Showing {len(filtered_df)} of {len(df)} indicators**")
        
        # Key metrics
        self.render_key_metrics(filtered_df, summary_data)
        
        st.markdown("---")
        
        # Threat analysis
        self.render_threat_distribution(filtered_df)
        
        st.markdown("---")
        
        # Confidence analysis
        self.render_confidence_analysis(filtered_df)
        
        st.markdown("---")
        
        # Geographic analysis
        self.render_geographic_analysis(filtered_df)
        
        st.markdown("---")
        
        # Temporal analysis
        self.render_temporal_analysis(filtered_df)
        
        st.markdown("---")
        
        # Source analysis
        self.render_source_analysis(filtered_df)
        
        st.markdown("---")
        
        # Network analysis
        self.render_network_analysis(filtered_df)
        
        st.markdown("---")
        
        # Detailed table
        self.render_indicator_details(filtered_df)
        
        # Footer
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center; color: #666; padding: 1rem;">
            🛡️ OSINT Threat Intelligence Dashboard | 
            Data Last Updated: {last_update} | 
            Built with Streamlit
        </div>
        """.format(
            last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ), unsafe_allow_html=True)


def main():
    """Main dashboard application."""
    dashboard = OSINTDashboard()
    dashboard.render_dashboard()


if __name__ == "__main__":
    main()