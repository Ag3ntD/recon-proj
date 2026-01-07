#!/usr/bin/env python3
"""
Database Models for Recon Pipeline
Supports both SQLite and PostgreSQL
"""

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, 
    Boolean, Text, Float, ForeignKey, JSON, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import json

Base = declarative_base()


class Target(Base):
    """Target domain being scanned"""
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(50), default='active')  # active, paused, completed
    
    # Relationships
    subdomains = relationship("Subdomain", back_populates="target", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Target(domain='{self.domain}', status='{self.status}')>"


class Scan(Base):
    """Scan execution record"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    scan_type = Column(String(50), nullable=False)  # passive, active, vuln, js
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), default='running')  # running, completed, failed
    error_message = Column(Text, nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_scan_target_type', 'target_id', 'scan_type'),
    )
    
    def __repr__(self):
        return f"<Scan(id={self.id}, type='{self.scan_type}', status='{self.status}')>"


class Subdomain(Base):
    """Discovered subdomains"""
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    subdomain = Column(String(255), nullable=False, index=True)
    source = Column(String(100))  # Tool that found it
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Live host information
    is_live = Column(Boolean, default=False)
    http_status = Column(Integer, nullable=True)
    http_title = Column(String(255), nullable=True)
    technologies = Column(JSON, nullable=True)  # Tech stack detected
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    
    # DNS records
    dns_records = Column(JSON, nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="subdomains")
    urls = relationship("URL", back_populates="subdomain", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_subdomain_target', 'target_id', 'subdomain', unique=True),
        Index('idx_subdomain_live', 'is_live'),
    )
    
    def __repr__(self):
        return f"<Subdomain(subdomain='{self.subdomain}', live={self.is_live})>"


class URL(Base):
    """Discovered URLs"""
    __tablename__ = 'urls'
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'), nullable=False)
    url = Column(Text, nullable=False)
    normalized_url = Column(String(500), index=True)  # For deduplication
    source = Column(String(100))  # wayback, gau, crawler
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # URL metadata
    http_method = Column(String(10), default='GET')
    parameters = Column(JSON, nullable=True)
    
    # Analysis flags
    has_parameters = Column(Boolean, default=False)
    is_javascript = Column(Boolean, default=False)
    is_api_endpoint = Column(Boolean, default=False)
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="urls")
    
    __table_args__ = (
        Index('idx_url_normalized', 'normalized_url'),
        Index('idx_url_parameters', 'has_parameters'),
    )
    
    def __repr__(self):
        return f"<URL(url='{self.url[:50]}...')>"


class Finding(Base):
    """Vulnerability findings"""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    # Finding metadata
    finding_type = Column(String(100), nullable=False)  # xss, sqli, ssrf, etc.
    severity = Column(String(20), nullable=False, index=True)  # info, low, medium, high, critical
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Location
    host = Column(String(255), nullable=False)
    url = Column(Text, nullable=False)
    matched_at = Column(String(500), nullable=True)
    
    # Tool information
    tool = Column(String(100), nullable=False)
    template_id = Column(String(255), nullable=True)  # For nuclei
    cve_id = Column(String(50), nullable=True, index=True)
    cwe_id = Column(String(50), nullable=True)
    
    # Evidence
    evidence = Column(JSON, nullable=True)  # Request/response, PoC
    raw_output = Column(Text, nullable=True)
    
    # Status
    status = Column(String(50), default='new')  # new, investigating, confirmed, false_positive, fixed
    confidence = Column(Float, default=1.0)  # 0.0 to 1.0
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    
    __table_args__ = (
        Index('idx_finding_severity', 'severity'),
        Index('idx_finding_type', 'finding_type'),
        Index('idx_finding_status', 'status'),
        Index('idx_finding_cve', 'cve_id'),
    )
    
    def __repr__(self):
        return f"<Finding(type='{self.finding_type}', severity='{self.severity}', host='{self.host}')>"


class Secret(Base):
    """Secrets found in JavaScript and source code"""
    __tablename__ = 'secrets'
    
    id = Column(Integer, primary_key=True)
    
    # Secret metadata
    secret_type = Column(String(100), nullable=False)  # api_key, password, token, etc.
    detector = Column(String(100), nullable=False)  # trufflehog, secretfinder
    
    # Location
    source_url = Column(Text, nullable=False)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    
    # Secret content
    secret_value = Column(Text, nullable=False)
    context = Column(Text, nullable=True)  # Surrounding code
    
    # Verification
    verified = Column(Boolean, default=False)
    confidence = Column(Float, default=0.5)
    
    # Status
    status = Column(String(50), default='new')  # new, verified, false_positive, revoked
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_secret_type', 'secret_type'),
        Index('idx_secret_verified', 'verified'),
    )
    
    def __repr__(self):
        return f"<Secret(type='{self.secret_type}', verified={self.verified})>"


class JavaScript(Base):
    """JavaScript files discovered"""
    __tablename__ = 'javascript_files'
    
    id = Column(Integer, primary_key=True)
    
    # File metadata
    url = Column(Text, nullable=False, unique=True)
    subdomain = Column(String(255), index=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Analysis status
    analyzed = Column(Boolean, default=False)
    analysis_date = Column(DateTime, nullable=True)
    
    # Extracted data
    urls_found = Column(Integer, default=0)
    endpoints_found = Column(Integer, default=0)
    secrets_found = Column(Integer, default=0)
    
    # File hash for change detection
    file_hash = Column(String(64), nullable=True)
    
    __table_args__ = (
        Index('idx_js_analyzed', 'analyzed'),
        Index('idx_js_subdomain', 'subdomain'),
    )
    
    def __repr__(self):
        return f"<JavaScript(url='{self.url[:50]}...', analyzed={self.analyzed})>"


class Notification(Base):
    """Notification log"""
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    
    # Notification metadata
    notification_type = Column(String(50), nullable=False)  # slack, discord, email
    severity = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    
    # Status
    sent = Column(Boolean, default=False)
    sent_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    
    # Related finding
    finding_id = Column(Integer, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Notification(type='{self.notification_type}', sent={self.sent})>"


class DatabaseManager:
    """Database connection and session management"""
    
    def __init__(self, config):
        self.config = config
        self.engine = None
        self.Session = None
        
    def initialize(self):
        """Initialize database connection"""
        db_type = self.config.get('database', {}).get('type', 'sqlite')
        
        if db_type == 'sqlite':
            db_path = self.config.get('database', {}).get('sqlite', {}).get('path', 'data/recon.db')
            connection_string = f"sqlite:///{db_path}"
        elif db_type == 'postgresql':
            pg_config = self.config.get('database', {}).get('postgresql', {})
            connection_string = (
                f"postgresql://{pg_config['user']}:{pg_config['password']}"
                f"@{pg_config['host']}:{pg_config['port']}/{pg_config['database']}"
            )
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
        
        self.engine = create_engine(connection_string, echo=False)
        self.Session = sessionmaker(bind=self.engine)
        
        # Create all tables
        Base.metadata.create_all(self.engine)
        
    def get_session(self):
        """Get a new database session"""
        if not self.Session:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.Session()
    
    def close(self):
        """Close database connection"""
        if self.engine:
            self.engine.dispose()
