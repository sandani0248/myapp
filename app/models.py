# File: app/models.py (Corrected Indentation)
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
# from sqlalchemy import (
#     CheckConstraint,      # For validation rules
#     UniqueConstraint,     # For unique columns
#     Index,                # For database indexes
#     ForeignKey,           # Already used (via db.ForeignKey)
#     or_, and_,            # For complex queries
# )
from sqlalchemy import CheckConstraint
import datetime # Make sure datetime is imported


# --- Association Table for EC2Instance <-> SecurityGroup (Many-to-Many) ---
instance_sg_association = db.Table('instance_sg_association',
    db.Column('ec2_instance_id', db.Integer, db.ForeignKey('instances.id', ondelete='CASCADE'), primary_key=True),
    db.Column('sg_id', db.Integer, db.ForeignKey('security_groups.id', ondelete='CASCADE'), primary_key=True)
)

# --- (FIX) ASSOCIATION TABLE FOR EC2Instance <-> BackupGroup ---
# This MUST be at the top level (no indentation)
instance_backup_group_association = db.Table('instance_backup_group_association',
    db.Column('ec2_instance_id', db.Integer, db.ForeignKey('instances.id', ondelete='CASCADE'), primary_key=True),
    db.Column('backup_group_id', db.Integer, db.ForeignKey('backup_groups.id', ondelete='CASCADE'), primary_key=True)
)
# --- END FIX ---


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    aws_credentials = db.relationship('AWSCredentials', back_populates='owner', cascade="all, delete-orphan", lazy='dynamic')
    
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash or "", password)
    def __repr__(self): return f'<User {self.username}>'

class AWSCredentials(db.Model):
    __tablename__ = 'aws_credentials'
    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(120), nullable=False, index=True, unique=True)
    auth_type = db.Column(db.String(20), nullable=False)
    aws_access_key_id = db.Column(db.String(120), nullable=True)
    encrypted_aws_secret_access_key = db.Column(db.String(512), nullable=True)
    role_arn = db.Column(db.String(255), nullable=True)
    default_region = db.Column(db.String(32), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    last_sync_status = db.Column(db.String(255), default='Never Synced')
    last_sync_time = db.Column(db.DateTime, nullable=True)
    server_username = db.Column(db.String(120), nullable=True, default='ec2-user')
    encrypted_server_password = db.Column(db.String(512), nullable=True)
    encrypted_pem_key = db.Column(db.Text, nullable=True)

    owner = db.relationship('User', back_populates='aws_credentials')
    instances = db.relationship('EC2Instance', back_populates='aws_account', cascade="all, delete-orphan")
    vpcs = db.relationship('VPC', back_populates='aws_account', cascade="all, delete-orphan")
    subnets = db.relationship('Subnet', back_populates='aws_account', cascade="all, delete-orphan")
    security_groups = db.relationship('SecurityGroup', back_populates='aws_account', cascade="all, delete-orphan")
    route_tables = db.relationship('RouteTable', back_populates='aws_account', cascade="all, delete-orphan")
    enis = db.relationship('ENI', back_populates='aws_account', cascade="all, delete-orphan")
    elastic_ips = db.relationship('ElasticIP', back_populates='aws_account', cascade="all, delete-orphan")
    amis = db.relationship('AMI', back_populates='aws_account', cascade="all, delete-orphan")
    snapshots = db.relationship('Snapshot', back_populates='aws_account', cascade="all, delete-orphan")
    backup_groups = db.relationship('BackupGroup', back_populates='aws_account', cascade="all, delete-orphan") # Add link to backup groups

    def __repr__(self): return f'<AWSCredentials {self.account_name}>'

class EC2Instance(db.Model):
    __tablename__ = 'instances'
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(255), index=True, nullable=True)
    instance_type = db.Column(db.String(64), nullable=True)
    state = db.Column(db.String(32), nullable=True)
    region = db.Column(db.String(32), index=True, nullable=True)
    private_ip = db.Column(db.String(45), nullable=True)
    public_ip = db.Column(db.String(45), nullable=True)
    launch_time = db.Column(db.DateTime, nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    ami_id_str = db.Column(db.String(64), index=True, nullable=True)
    vpc_id_str = db.Column(db.String(64), db.ForeignKey('vpcs.vpc_id', ondelete='SET NULL'), index=True, nullable=True)
    subnet_id_str = db.Column(db.String(64), db.ForeignKey('subnets.subnet_id', ondelete='SET NULL'), index=True, nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='instances')
    security_groups = db.relationship('SecurityGroup', secondary=instance_sg_association, back_populates='instances')
    
    # --- (FIX) ADD THIS RELATIONSHIP *INSIDE* THE EC2Instance CLASS ---
    backup_groups = db.relationship('BackupGroup', secondary=instance_backup_group_association,
                                    back_populates='instances')
    # --- END FIX ---
    
    ami = db.relationship('AMI', foreign_keys=[ami_id_str], primaryjoin="EC2Instance.ami_id_str == AMI.image_id", backref=db.backref('instances_using', lazy='dynamic'))
    vpc = db.relationship('VPC', foreign_keys=[vpc_id_str], primaryjoin="EC2Instance.vpc_id_str == VPC.vpc_id", backref=db.backref('instances_in', lazy='dynamic'))
    subnet = db.relationship('Subnet', foreign_keys=[subnet_id_str], primaryjoin="EC2Instance.subnet_id_str == Subnet.subnet_id", backref=db.backref('instances_in', lazy='dynamic'))

    def __repr__(self): return f'<EC2Instance {self.instance_id}>'

class VPC(db.Model):
    __tablename__ = 'vpcs'
    id = db.Column(db.Integer, primary_key=True)
    vpc_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    region = db.Column(db.String(32), index=True)
    cidr_block = db.Column(db.String(64), nullable=True)
    is_default = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(255), index=True, nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='vpcs')

class Subnet(db.Model):
    __tablename__ = 'subnets'
    id = db.Column(db.Integer, primary_key=True)
    subnet_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    vpc_id_str = db.Column(db.String(64), db.ForeignKey('vpcs.vpc_id', ondelete='SET NULL'), index=True)
    region = db.Column(db.String(32), index=True)
    cidr_block = db.Column(db.String(64), nullable=True)
    availability_zone = db.Column(db.String(32), nullable=True)
    name = db.Column(db.String(255), index=True, nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='subnets')
    vpc = db.relationship('VPC', foreign_keys=[vpc_id_str], backref=db.backref('subnets', lazy='dynamic'))

class SecurityGroup(db.Model):
    __tablename__ = 'security_groups'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    vpc_id_str = db.Column(db.String(64), db.ForeignKey('vpcs.vpc_id', ondelete='SET NULL'), index=True)
    region = db.Column(db.String(32), index=True)
    group_name = db.Column(db.String(255), index=True, nullable=True)
    description = db.Column(db.String(1024), nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='security_groups')
    vpc = db.relationship('VPC', foreign_keys=[vpc_id_str], backref=db.backref('security_groups', lazy='dynamic'))
    rules = db.relationship('SecurityGroupRule', back_populates='security_group', cascade="all, delete-orphan")
    instances = db.relationship('EC2Instance', secondary=instance_sg_association, back_populates='security_groups')

class SecurityGroupRule(db.Model):
    __tablename__ = 'security_group_rules'
    id = db.Column(db.Integer, primary_key=True)
    sg_id = db.Column(db.Integer, db.ForeignKey('security_groups.id', ondelete='CASCADE'), nullable=False)
    rule_type = db.Column(db.String(10), nullable=True)
    protocol = db.Column(db.String(32), nullable=True)
    from_port = db.Column(db.Integer, nullable=True)
    to_port = db.Column(db.Integer, nullable=True)
    cidr_ipv4 = db.Column(db.String(128), nullable=True)
    source_security_group_id = db.Column(db.String(64), nullable=True)
    
    security_group = db.relationship('SecurityGroup', back_populates='rules')

class RouteTable(db.Model):
    __tablename__ = 'route_tables'
    id = db.Column(db.Integer, primary_key=True)
    route_table_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    vpc_id_str = db.Column(db.String(64), db.ForeignKey('vpcs.vpc_id', ondelete='SET NULL'), index=True)
    region = db.Column(db.String(32), index=True)
    name = db.Column(db.String(255), index=True, nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='route_tables')
    vpc = db.relationship('VPC', foreign_keys=[vpc_id_str], backref=db.backref('route_tables', lazy='dynamic'))
    routes = db.relationship('Route', back_populates='route_table', cascade="all, delete-orphan")

class Route(db.Model):
    __tablename__ = 'routes'
    id = db.Column(db.Integer, primary_key=True)
    route_table_id_int = db.Column(db.Integer, db.ForeignKey('route_tables.id', ondelete='CASCADE'), nullable=False)
    destination_cidr = db.Column(db.String(64), nullable=True)
    target_gateway_id = db.Column(db.String(64), nullable=True)
    target_instance_id = db.Column(db.String(64), nullable=True)
    target_eni_id = db.Column(db.String(64), nullable=True)
    origin = db.Column(db.String(64), nullable=True)
    
    route_table = db.relationship('RouteTable', back_populates='routes')

class ENI(db.Model):
    __tablename__ = 'enis'
    id = db.Column(db.Integer, primary_key=True)
    eni_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    subnet_id_str = db.Column(db.String(64), db.ForeignKey('subnets.subnet_id', ondelete='SET NULL'), index=True)
    region = db.Column(db.String(32), index=True)
    status = db.Column(db.String(32), nullable=True)
    description = db.Column(db.String(1024), nullable=True)
    private_ip = db.Column(db.String(45), nullable=True)
    public_ip = db.Column(db.String(45), nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='enis')
    subnet = db.relationship('Subnet', foreign_keys=[subnet_id_str], backref=db.backref('enis', lazy='dynamic'))

class ElasticIP(db.Model):
    __tablename__ = 'elastic_ips'
    id = db.Column(db.Integer, primary_key=True)
    public_ip = db.Column(db.String(45), index=True, nullable=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    region = db.Column(db.String(32), index=True)
    allocation_id = db.Column(db.String(64), unique=True, index=True)
    eni_id_str = db.Column(db.String(64), nullable=True)
    instance_id_str = db.Column(db.String(64), nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='elastic_ips')

class AMI(db.Model):
    __tablename__ = 'amis'
    id = db.Column(db.Integer, primary_key=True)
    image_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    region = db.Column(db.String(32), index=True)
    name = db.Column(db.String(255), index=True, nullable=True)
    creation_date = db.Column(db.DateTime, nullable=True)
    owner_id = db.Column(db.String(64), nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    tags = db.Column(db.JSON, nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='amis')
    # instances_using backref defined in EC2Instance

class Snapshot(db.Model):
    __tablename__ = 'snapshots'
    id = db.Column(db.Integer, primary_key=True)
    snapshot_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    region = db.Column(db.String(32), index=True)
    volume_id = db.Column(db.String(64), nullable=True)
    start_time = db.Column(db.DateTime, nullable=True)
    volume_size_gb = db.Column(db.Integer, nullable=True)
    state = db.Column(db.String(32), nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    
    aws_account = db.relationship('AWSCredentials', back_populates='snapshots')


# --- (FIX) ALL NEW BACKUP MODELS AT TOP LEVEL (no indentation) ---

class BackupGroup(db.Model):
    """Represents a logical group of instances for backup purposes."""
    __tablename__ = 'backup_groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, index=True)
    aws_account_id = db.Column(db.Integer, db.ForeignKey('aws_credentials.id', ondelete='CASCADE'), nullable=False)
    
    aws_account = db.relationship('AWSCredentials', back_populates='backup_groups')
    policy = db.relationship('BackupPolicy', back_populates='group', uselist=False, cascade="all, delete-orphan")
    instances = db.relationship('EC2Instance', secondary=instance_backup_group_association,
                                back_populates='backup_groups', lazy='dynamic')
    logs = db.relationship('BackupJobLog', back_populates='group', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<BackupGroup {self.name}>'

# class BackupPolicy(db.Model):
#     """Defines the schedule and retention for a specific BackupGroup."""
#     __tablename__ = 'backup_policies'
#     id = db.Column(db.Integer, primary_key=True)
#     group_id = db.Column(db.Integer, db.ForeignKey('backup_groups.id', ondelete='CASCADE'), unique=True, nullable=False)
    
#     # Hybrid backup strategy
#     backup_strategy = db.Column(db.String(20), nullable=False, default='hybrid')  # 'ami_only', 'snapshot_only', 'hybrid'
    
#     # AMI backup frequency
#     ami_interval_value = db.Column(db.Integer, nullable=False, default=1)
#     ami_interval_unit = db.Column(db.String(20), nullable=False, default='hours')  # 'minutes', 'hours', 'days'
    
#     # Snapshot backup frequency (for hybrid/snapshot_only)
#     snapshot_interval_value = db.Column(db.Integer, nullable=False, default=5)
#     snapshot_interval_unit = db.Column(db.String(20), nullable=False, default='minutes')  # 'minutes', 'hours'
    
#     # Retention
#     retention_days = db.Column(db.Integer, nullable=False, default=7)
#     retention_count = db.Column(db.Integer, nullable=True)  # Alternative: keep last N backups
    
#     # Tracking
#     last_ami_time = db.Column(db.DateTime, nullable=True)
#     last_snapshot_time = db.Column(db.DateTime, nullable=True)
#     last_run_time = db.Column(db.DateTime, nullable=True)  # Keep for compatibility
    
#     is_active = db.Column(db.Boolean, default=True, nullable=False)

#     group = db.relationship('BackupGroup', back_populates='policy')

#     def __repr__(self):
#         return f'<BackupPolicy for Group {self.group_id}>'

class BackupPolicy(db.Model):
    """
    Defines the schedule and retention for a specific BackupGroup.
    
    Supports hybrid backup strategy:
    - AMI backups: Full system image (slower but comprehensive)
    - Snapshot backups: Volume-level incremental (faster but restore is more complex)
    
    Interval units:
    - 'minutes': 1-59 minutes between backups
    - 'hourly': 1-24 hours between backups
    - 'days': 1-365 days between backups
    - 'weekly': 1-52 weeks between backups
    - 'monthly': 1-12 months between backups
    - 'yearly': Annual backups
    """
    __tablename__ = 'backup_policies'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(
        db.Integer, 
        db.ForeignKey('backup_groups.id', ondelete='CASCADE'), 
        unique=True, 
        nullable=False
    )
    
    # Backup strategy: 'ami_only', 'snapshot_only', or 'hybrid'
    backup_strategy = db.Column(
        db.String(20), 
        nullable=False, 
        default='hybrid'
    )
    
    # ===== AMI BACKUP SCHEDULE =====
    ami_interval_value = db.Column(db.Integer, nullable=False, default=1)
    ami_interval_unit = db.Column(
        db.String(20), 
        nullable=False, 
        default='days'
    )
    
    # ===== SNAPSHOT BACKUP SCHEDULE =====
    snapshot_interval_value = db.Column(db.Integer, nullable=False, default=5)
    snapshot_interval_unit = db.Column(
        db.String(20), 
        nullable=False, 
        default='minutes'
    )
    
    # ===== RETENTION POLICY =====
    # Either retention_days OR retention_count (not both)
    retention_days = db.Column(db.Integer, nullable=True, default=7)
    retention_count = db.Column(db.Integer, nullable=True)
    
    # ===== SCHEDULING TRACKING =====
    last_ami_time = db.Column(db.DateTime, nullable=True)
    last_snapshot_time = db.Column(db.DateTime, nullable=True)
    
    # ===== STATUS =====
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    # created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # updated_at = db.Column(
    #     db.DateTime, 
    #     default=datetime.datetime.utcnow, 
    #     onupdate=datetime.datetime.utcnow
    # )

    group = db.relationship('BackupGroup', back_populates='policy')

    # Validation constraints
    __table_args__ = (
        CheckConstraint('ami_interval_value > 0', name='check_ami_interval_positive'),
        CheckConstraint('snapshot_interval_value > 0', name='check_snap_interval_positive'),
        CheckConstraint(
            "ami_interval_unit IN ('minutes', 'hourly', 'days', 'weekly', 'monthly', 'yearly')",
            name='check_valid_ami_unit'
        ),
        CheckConstraint(
            "snapshot_interval_unit IN ('minutes', 'hourly', 'days', 'weekly')",
            name='check_valid_snap_unit'
        ),
    )

    def __repr__(self):
        return f'<BackupPolicy Group:{self.group_id} Strategy:{self.backup_strategy}>'

    def get_display_interval(self, backup_type='ami'):
        """Get human-readable interval string"""
        if backup_type == 'ami':
            value = self.ami_interval_value
            unit = self.ami_interval_unit
        else:
            value = self.snapshot_interval_value
            unit = self.snapshot_interval_unit
        
        unit_display = {
            'minutes': 'min',
            'hourly': 'hr',
            'days': 'day',
            'weekly': 'wk',
            'monthly': 'mo',
            'yearly': 'yr'
        }
        
        return f"Every {value} {unit_display.get(unit, unit)}"



# class BackupJobLog(db.Model):
#     """Logs the result of each backup job run for a specific instance."""
#     __tablename__ = 'backup_job_logs'
#     id = db.Column(db.Integer, primary_key=True)
#     group_id = db.Column(db.Integer, db.ForeignKey('backup_groups.id', ondelete='SET NULL'), nullable=True)
#     instance_id_str = db.Column(db.String(64), index=True, nullable=False)
#     status = db.Column(db.String(50), nullable=False, default='Pending') # Pending, Success, Failed, In Progress
#     message = db.Column(db.Text, nullable=True)
#     start_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
#     end_time = db.Column(db.DateTime, nullable=True)
    
#     # Backup type and relationships
#     backup_type = db.Column(db.String(20), nullable=False, default='ami')  # 'ami' or 'snapshot'
#     parent_ami_id = db.Column(db.String(64), nullable=True)  # Reference AMI for snapshot-only backups
#     is_incremental = db.Column(db.Boolean, default=False)
    
#     # AMI and snapshots
#     ami_id_str = db.Column(db.String(64), nullable=True)
#     snapshots_created = db.Column(db.JSON, nullable=True)  # [{snapshot_id, volume_id, device_name, size}]
    
#     # Instance configuration
#     instance_type = db.Column(db.String(64), nullable=True)
#     ami_used = db.Column(db.String(64), nullable=True)  # AMI the instance was running
#     key_pair_name = db.Column(db.String(255), nullable=True)
#     iam_role_arn = db.Column(db.String(512), nullable=True)
    
#     # Network configuration
#     vpc_id_str = db.Column(db.String(64), nullable=True)
#     subnet_id_str = db.Column(db.String(64), nullable=True)
#     availability_zone = db.Column(db.String(64), nullable=True)
#     security_group_ids = db.Column(db.JSON, nullable=True)  # List of SG IDs
#     private_ip = db.Column(db.String(45), nullable=True)
#     public_ip = db.Column(db.String(45), nullable=True)
#     elastic_ip_allocation_id = db.Column(db.String(64), nullable=True)
    
#     # Additional metadata
#     region = db.Column(db.String(32), nullable=True)
#     tags = db.Column(db.JSON, nullable=True)
#     user_data = db.Column(db.Text, nullable=True)  # Base64 encoded
    
#     group = db.relationship('BackupGroup', back_populates='logs')

class BackupJobLog(db.Model):
    """
    Logs each backup execution with detailed metadata for recovery and troubleshooting.
    """
    __tablename__ = 'backup_job_logs'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(
        db.Integer, 
        db.ForeignKey('backup_groups.id', ondelete='SET NULL'), 
        nullable=True
    )
    instance_id_str = db.Column(db.String(64), index=True, nullable=False)
    
    # ===== EXECUTION STATUS =====
    status = db.Column(
        db.String(50), 
        nullable=False, 
        default='Pending'
    )
    # Valid: Pending, In Progress, Success, Failed, Cleaned
    
    message = db.Column(db.Text, nullable=True)  # Error message if failed
    
    # ===== TIMING =====
    start_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    # duration_seconds = db.Column(db.Integer, nullable=True)  # Computed from end-start
    
    # ===== BACKUP DETAILS =====
    backup_type = db.Column(db.String(20), nullable=False, default='ami')  # 'ami' or 'snapshot'
    
    # AMI backup results
    ami_id_str = db.Column(db.String(64), nullable=True)
    # ami_size_gb = db.Column(db.Integer, nullable=True)
    
    # Snapshot backup results
    snapshots_created = db.Column(db.JSON, nullable=True)
    # Format: [{snapshot_id, volume_id, device_name, size_gb}, ...]
    # snapshot_size_gb = db.Column(db.Integer, nullable=True)
    
    # ===== INSTANCE CONFIGURATION AT BACKUP TIME =====
    instance_type = db.Column(db.String(64), nullable=True)
    ami_used = db.Column(db.String(64), nullable=True)
    key_pair_name = db.Column(db.String(255), nullable=True)
    iam_role_arn = db.Column(db.String(512), nullable=True)
    
    # ===== NETWORK CONFIGURATION AT BACKUP TIME =====
    vpc_id_str = db.Column(db.String(64), nullable=True)
    subnet_id_str = db.Column(db.String(64), nullable=True)
    availability_zone = db.Column(db.String(64), nullable=True)
    security_group_ids = db.Column(db.JSON, nullable=True)
    private_ip = db.Column(db.String(45), nullable=True)
    public_ip = db.Column(db.String(45), nullable=True)
    elastic_ip_allocation_id = db.Column(db.String(64), nullable=True)
    
    # ===== METADATA & TAGS =====
    region = db.Column(db.String(32), nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    user_data = db.Column(db.Text, nullable=True)  # Base64 encoded
    
    # ===== RETRY & COST TRACKING =====
    # retry_count = db.Column(db.Integer, default=0)
    # estimated_cost = db.Column(db.Float, nullable=True)  # Storage cost in USD
    parent_ami_id = db.Column(db.String(64), nullable=True)
    is_incremental = db.Column(db.Boolean, default=False)

    group = db.relationship('BackupGroup', back_populates='logs')

    def __repr__(self):
        return f'<BackupJobLog {self.instance_id_str} {self.status}>'

    def calculate_duration(self):
        """Calculate backup duration in seconds"""
        if self.start_time and self.end_time:
            self.duration_seconds = int((self.end_time - self.start_time).total_seconds())
            return self.duration_seconds
        return None

# --- (FIX) REMOVED THE OBSOLETE ServerCredential MODEL ---
# (The model previously defined here was removed as its fields were merged into AWSCredentials)