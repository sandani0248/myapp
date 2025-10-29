# File: app/services/backup_service.py
"""
Backup Service - Handles hybrid backup execution and restoration
"""
import boto3
from datetime import datetime, timedelta
from flask import current_app
from app import db
from app.models import BackupGroup, BackupPolicy, BackupJobLog, EC2Instance, AWSCredentials
from app.services.aws_service import AWSService
import json
import base64


class BackupService:
    """
    Manages backup execution using hybrid AMI + Snapshot strategy
    """
    
    def __init__(self, aws_credentials: AWSCredentials):
        self.credentials = aws_credentials
        self.aws_service = AWSService(aws_credentials)
        self.session = self.aws_service.session
    
    def should_create_ami(self, instance: EC2Instance, policy: BackupPolicy) -> bool:
        """
        Determines if we should create full AMI or just snapshots
        """
        if policy.backup_strategy == 'snapshot_only':
            # Never create AMI, only snapshots
            return False
        
        if policy.backup_strategy == 'ami_only':
            # Always create AMI
            return True
        
        # Hybrid strategy logic
        if not policy.last_ami_time:
            # First backup ever - create AMI
            return True
        
        # Calculate AMI interval in minutes
        ami_interval_minutes = self._get_interval_minutes(
            policy.ami_interval_value, 
            policy.ami_interval_unit
        )
        
        time_since_last_ami = datetime.utcnow() - policy.last_ami_time
        
        if time_since_last_ami.total_seconds() / 60 >= ami_interval_minutes:
            # Time for periodic AMI
            return True
        
        return False
    
    def _get_interval_minutes(self, value: int, unit: str) -> int:
        """Convert interval to minutes"""
        if unit == 'minutes':
            return value
        elif unit == 'hours':
            return value * 60
        elif unit == 'days':
            return value * 1440
        return 60  # Default to 1 hour
    
    def execute_backup(self, group_id: int):
        """
        Execute backup for all instances in a group
        """
        group = BackupGroup.query.get(group_id)
        if not group or not group.policy or not group.policy.is_active:
            current_app.logger.warning(f"Backup group {group_id} not found or not active")
            return
        
        policy = group.policy
        results = []
        
        for instance in group.instances:
            try:
                if self.should_create_ami(instance, policy):
                    # Full AMI backup
                    result = self._create_ami_backup(instance, group)
                    policy.last_ami_time = datetime.utcnow()
                else:
                    # Snapshot-only backup
                    result = self._create_snapshot_backup(instance, group)
                
                policy.last_snapshot_time = datetime.utcnow()
                policy.last_run_time = datetime.utcnow()
                results.append(result)
                
            except Exception as e:
                current_app.logger.error(f"Backup failed for {instance.instance_id}: {e}", exc_info=True)
                # Log failure
                log = BackupJobLog(
                    group_id=group.id,
                    instance_id_str=instance.instance_id,
                    status='Failed',
                    message=str(e),
                    start_time=datetime.utcnow(),
                    end_time=datetime.utcnow()
                )
                db.session.add(log)
        
        db.session.commit()
        return results
    
    def _create_ami_backup(self, instance: EC2Instance, group: BackupGroup):
        """
        Create full AMI backup with all metadata
        """
        start_time = datetime.utcnow()
        
        # Create backup log
        log = BackupJobLog(
            group_id=group.id,
            instance_id_str=instance.instance_id,
            status='In Progress',
            backup_type='ami',
            is_incremental=False,
            start_time=start_time
        )
        db.session.add(log)
        db.session.commit()
        
        try:
            ec2_client = self.session.client('ec2', region_name=instance.region)
            
            # Capture instance metadata BEFORE creating AMI
            metadata = self._capture_instance_metadata(instance, ec2_client)
            
            # Create AMI (NoReboot=True for minimal disruption)
            ami_name = f"{instance.name or instance.instance_id}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            response = ec2_client.create_image(
                InstanceId=instance.instance_id,
                Name=ami_name,
                Description=f"Automated backup from group: {group.name}",
                NoReboot=True,
                TagSpecifications=[{
                    'ResourceType': 'image',
                    'Tags': [
                        {'Key': 'BackupGroup', 'Value': group.name},
                        {'Key': 'SourceInstance', 'Value': instance.instance_id},
                        {'Key': 'CreatedBy', 'Value': 'AWS-Dashboard'},
                        {'Key': 'BackupType', 'Value': 'AMI'},
                        {'Key': 'Timestamp', 'Value': start_time.isoformat()}
                    ]
                }]
            )
            
            ami_id = response['ImageId']
            
            # Get snapshot IDs from AMI
            waiter = ec2_client.get_waiter('image_available')
            # Don't wait synchronously - check status later
            
            # Get snapshots associated with AMI
            ami_details = ec2_client.describe_images(ImageIds=[ami_id])['Images'][0]
            snapshots = []
            for bdm in ami_details.get('BlockDeviceMappings', []):
                if 'Ebs' in bdm:
                    snapshots.append({
                        'snapshot_id': bdm['Ebs']['SnapshotId'],
                        'device_name': bdm['DeviceName'],
                        'volume_size': bdm['Ebs'].get('VolumeSize'),
                        'volume_type': bdm['Ebs'].get('VolumeType')
                    })
            
            # Update log with success
            log.status = 'Success'
            log.ami_id_str = ami_id
            log.snapshots_created = snapshots
            log.end_time = datetime.utcnow()
            
            # Store all metadata
            self._store_metadata_in_log(log, metadata)
            
            db.session.commit()
            
            current_app.logger.info(f"AMI backup created: {ami_id} for {instance.instance_id}")
            return {'success': True, 'ami_id': ami_id, 'log_id': log.id}
            
        except Exception as e:
            log.status = 'Failed'
            log.message = str(e)
            log.end_time = datetime.utcnow()
            db.session.commit()
            raise
    
    def _create_snapshot_backup(self, instance: EC2Instance, group: BackupGroup):
        """
        Create snapshot-only backup (incremental)
        """
        start_time = datetime.utcnow()
        
        # Find most recent AMI backup to use as parent
        parent_ami_log = BackupJobLog.query.filter_by(
            instance_id_str=instance.instance_id,
            backup_type='ami',
            status='Success'
        ).order_by(BackupJobLog.start_time.desc()).first()
        
        if not parent_ami_log:
            # No AMI exists - force AMI creation instead
            current_app.logger.warning(f"No parent AMI found for {instance.instance_id}, creating AMI")
            return self._create_ami_backup(instance, group)
        
        # Create backup log
        log = BackupJobLog(
            group_id=group.id,
            instance_id_str=instance.instance_id,
            status='In Progress',
            backup_type='snapshot',
            parent_ami_id=parent_ami_log.ami_id_str,
            is_incremental=True,
            start_time=start_time
        )
        db.session.add(log)
        db.session.commit()
        
        try:
            ec2_client = self.session.client('ec2', region_name=instance.region)
            
            # Capture current metadata
            metadata = self._capture_instance_metadata(instance, ec2_client)
            
            # Get all volumes attached to instance
            volumes_response = ec2_client.describe_volumes(
                Filters=[{
                    'Name': 'attachment.instance-id',
                    'Values': [instance.instance_id]
                }]
            )
            
            snapshots = []
            for volume in volumes_response['Volumes']:
                volume_id = volume['VolumeId']
                device_name = volume['Attachments'][0]['Device']
                
                # Create snapshot (AWS handles incremental logic automatically)
                snapshot_response = ec2_client.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"Incremental backup for {instance.instance_id}",
                    TagSpecifications=[{
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {'Key': 'BackupGroup', 'Value': group.name},
                            {'Key': 'SourceInstance', 'Value': instance.instance_id},
                            {'Key': 'BackupType', 'Value': 'Incremental'},
                            {'Key': 'ParentAMI', 'Value': parent_ami_log.ami_id_str},
                            {'Key': 'CreatedBy', 'Value': 'AWS-Dashboard'},
                            {'Key': 'Timestamp', 'Value': start_time.isoformat()}
                        ]
                    }]
                )
                
                snapshots.append({
                    'snapshot_id': snapshot_response['SnapshotId'],
                    'volume_id': volume_id,
                    'device_name': device_name,
                    'volume_size': volume['Size'],
                    'volume_type': volume['VolumeType']
                })
            
            # Update log
            log.status = 'Success'
            log.snapshots_created = snapshots
            log.end_time = datetime.utcnow()
            
            # Store metadata
            self._store_metadata_in_log(log, metadata)
            
            db.session.commit()
            
            current_app.logger.info(f"Snapshot backup created for {instance.instance_id}: {len(snapshots)} snapshots")
            return {'success': True, 'snapshots': snapshots, 'log_id': log.id}
            
        except Exception as e:
            log.status = 'Failed'
            log.message = str(e)
            log.end_time = datetime.utcnow()
            db.session.commit()
            raise
    
    def _capture_instance_metadata(self, instance: EC2Instance, ec2_client):
        """
        Capture complete instance configuration
        """
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance.instance_id])
            inst_data = response['Reservations'][0]['Instances'][0]
            
            metadata = {
                'instance_type': inst_data.get('InstanceType'),
                'ami_id': inst_data.get('ImageId'),
                'key_pair_name': inst_data.get('KeyName'),
                'iam_role_arn': inst_data.get('IamInstanceProfile', {}).get('Arn'),
                'vpc_id': inst_data.get('VpcId'),
                'subnet_id': inst_data.get('SubnetId'),
                'availability_zone': inst_data.get('Placement', {}).get('AvailabilityZone'),
                'security_group_ids': [sg['GroupId'] for sg in inst_data.get('SecurityGroups', [])],
                'private_ip': inst_data.get('PrivateIpAddress'),
                'public_ip': inst_data.get('PublicIpAddress'),
                'region': instance.region,
                'tags': inst_data.get('Tags', [])
            }
            
            # Get Elastic IP if assigned
            if metadata['public_ip']:
                try:
                    eip_response = ec2_client.describe_addresses(
                        Filters=[{'Name': 'public-ip', 'Values': [metadata['public_ip']]}]
                    )
                    if eip_response['Addresses']:
                        metadata['elastic_ip_allocation_id'] = eip_response['Addresses'][0].get('AllocationId')
                except:
                    pass
            
            # Get user data
            try:
                user_data_response = ec2_client.describe_instance_attribute(
                    InstanceId=instance.instance_id,
                    Attribute='userData'
                )
                if 'UserData' in user_data_response and 'Value' in user_data_response['UserData']:
                    metadata['user_data'] = user_data_response['UserData']['Value']
            except:
                pass
            
            return metadata
            
        except Exception as e:
            current_app.logger.error(f"Error capturing metadata for {instance.instance_id}: {e}")
            return {}
    
    def _store_metadata_in_log(self, log: BackupJobLog, metadata: dict):
        """Store metadata in backup log"""
        log.instance_type = metadata.get('instance_type')
        log.ami_used = metadata.get('ami_id')
        log.key_pair_name = metadata.get('key_pair_name')
        log.iam_role_arn = metadata.get('iam_role_arn')
        log.vpc_id_str = metadata.get('vpc_id')
        log.subnet_id_str = metadata.get('subnet_id')
        log.availability_zone = metadata.get('availability_zone')
        log.security_group_ids = metadata.get('security_group_ids')
        log.private_ip = metadata.get('private_ip')
        log.public_ip = metadata.get('public_ip')
        log.elastic_ip_allocation_id = metadata.get('elastic_ip_allocation_id')
        log.region = metadata.get('region')
        log.tags = metadata.get('tags')
        log.user_data = metadata.get('user_data')
    
    def cleanup_old_backups(self, group_id: int):
        """
        Delete old backups based on retention policy
        """
        group = BackupGroup.query.get(group_id)
        if not group or not group.policy:
            return
        
        policy = group.policy
        ec2_client = self.session.client('ec2', region_name=group.instances[0].region if group.instances else 'us-east-1')
        
        # Get all successful backups for this group
        all_logs = BackupJobLog.query.filter_by(
            group_id=group_id,
            status='Success'
        ).order_by(BackupJobLog.start_time.desc()).all()
        
        logs_to_delete = []
        
        # Apply retention by count
        if policy.retention_count:
            logs_to_delete = all_logs[policy.retention_count:]
        
        # Apply retention by days
        if policy.retention_days:
            cutoff_date = datetime.utcnow() - timedelta(days=policy.retention_days)
            logs_to_delete = [log for log in all_logs if log.start_time < cutoff_date]
        
        # Delete old backups
        for log in logs_to_delete:
            try:
                # Delete AMI if exists
                if log.ami_id_str:
                    try:
                        ec2_client.deregister_image(ImageId=log.ami_id_str)
                        current_app.logger.info(f"Deleted AMI: {log.ami_id_str}")
                    except:
                        pass
                
                # Delete snapshots
                if log.snapshots_created:
                    for snap in log.snapshots_created:
                        try:
                            ec2_client.delete_snapshot(SnapshotId=snap['snapshot_id'])
                            current_app.logger.info(f"Deleted snapshot: {snap['snapshot_id']}")
                        except:
                            pass
                
                # Delete log from database
                db.session.delete(log)
                
            except Exception as e:
                current_app.logger.error(f"Error deleting backup {log.id}: {e}")
        
        db.session.commit()