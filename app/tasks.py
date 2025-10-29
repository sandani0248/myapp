from app.extensions import celery
from app.models import AWSCredentials, EC2Instance, BackupJobLog, BackupGroup, BackupPolicy
from app.services.aws_service import AWSService
from app import db
from flask import current_app
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError
from sqlalchemy import or_

@celery.task(bind=True)
def sync_inventory_task(self, account_id):
    """
    This is the background task that performs the full inventory sync.
    """
    aws_creds = AWSCredentials.query.get(account_id)
    if not aws_creds:
        current_app.logger.error(f"Sync task failed: Could not find AWSCredentials with ID {account_id}")
        return

    # Check if a sync is already in progress
    if aws_creds.last_sync_status == "Syncing in background...":
        current_app.logger.warning(f"Sync already in progress for {aws_creds.account_name}. Skipping task.")
        return

    current_app.logger.info(f"Starting background sync for account: {aws_creds.account_name}")
    aws_creds.last_sync_status = "Syncing in background..."
    db.session.commit()

    try:
        aws_service = AWSService(aws_creds)
        status = aws_service.sync_all_resources()
        
        aws_creds.last_sync_time = db.func.now()
        aws_creds.last_sync_status = status
        db.session.commit()
        current_app.logger.info(f"Sync successful for {aws_creds.account_name}")
        
    except Exception as e:
        db.session.rollback()
        error_msg = f"Background Sync Failed: {str(e)}"
        aws_creds.last_sync_status = error_msg
        db.session.commit()
        current_app.logger.error(f"Sync failed for account {aws_creds.account_name}: {e}", exc_info=True)


@celery.task(name='refresh_single_instance', bind=True, max_retries=3)
def refresh_single_instance(self, account_id, instance_id):
    """
    Refresh a single instance's state from AWS after actions like start/stop/reboot.
    Includes retry logic for state transitions.
    """
    try:
        account = AWSCredentials.query.get(account_id)
        if not account:
            current_app.logger.error(f"Account {account_id} not found for instance refresh")
            return {'success': False, 'message': 'Account not found'}
        
        inst = EC2Instance.query.filter_by(
            aws_account_id=account_id,
            instance_id=instance_id
        ).first()
        
        if not inst:
            current_app.logger.error(f"Instance {instance_id} not found in DB")
            return {'success': False, 'message': 'Instance not found'}
        
        # Get latest data from AWS
        aws_service = AWSService(account)
        ec2 = aws_service.session.client('ec2', region_name=inst.region)
        
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if not response['Reservations']:
            current_app.logger.error(f"Instance {instance_id} not found in AWS")
            return {'success': False, 'message': 'Instance not found in AWS'}
        
        # Update instance with latest AWS data
        for reservation in response['Reservations']:
            for aws_inst in reservation['Instances']:
                new_state = aws_inst['State']['Name']
                inst.state = new_state
                inst.public_ip = aws_inst.get('PublicIpAddress', None)
                inst.private_ip = aws_inst.get('PrivateIpAddress', None)
                inst.instance_type = aws_inst.get('InstanceType', inst.instance_type)
        
        db.session.commit()
        current_app.logger.info(f"Instance {instance_id} refreshed - State: {inst.state}")
        
        # If still in transitional state, retry after delay
        if inst.state in ['pending', 'stopping', 'rebooting', 'shutting-down']:
            current_app.logger.info(f"Instance {instance_id} still in transitional state '{inst.state}', retrying...")
            raise Exception(f"Instance still transitioning: {inst.state}")
        
        return {'success': True, 'message': f'Instance {instance_id} refreshed to final state: {inst.state}'}
        
    except Exception as e:
        db.session.rollback()
        retry_count = self.request.retries
        
        if retry_count < self.max_retries:
            # Retry with exponential backoff: 10s, 20s, 30s
            countdown = 10 * (retry_count + 1)
            current_app.logger.warning(f"Retrying instance refresh (attempt {retry_count + 1}/{self.max_retries}) in {countdown}s: {e}")
            raise self.retry(countdown=countdown)
        else:
            current_app.logger.error(f"Failed to refresh instance {instance_id} after {self.max_retries} retries: {e}", exc_info=True)
            return {'success': False, 'message': str(e)}


@celery.task
def check_and_execute_scheduled_backups():
    """Check for backup policies that need to run and execute them."""
    try:
        current_time = datetime.utcnow()
        policies = BackupPolicy.query.filter_by(is_active=True).all()
        executed_count = 0
        
        for policy in policies:
            should_run = False
            if policy.last_run_time is None:
                should_run = True
            else:
                if policy.interval_unit == 'minutes':
                    next_run = policy.last_run_time + timedelta(minutes=policy.interval_value)
                elif policy.interval_unit == 'hours':
                    next_run = policy.last_run_time + timedelta(hours=policy.interval_value)
                elif policy.interval_unit == 'days':
                    next_run = policy.last_run_time + timedelta(days=policy.interval_value)
                else:
                    continue
                should_run = current_time >= next_run
            
            if should_run:
                execute_backup_group_task.delay(policy.group_id)
                executed_count += 1
        
        return f"Scheduled backup check completed. {executed_count} backups triggered."
    except Exception as e:
        current_app.logger.error(f"Scheduled backup check failed: {e}")
        return f"Scheduled backup check failed: {str(e)}"


@celery.task(bind=True)
def execute_backup_group_task(self, group_id):
    """Execute backup for all instances in a backup group."""
    try:
        backup_group = BackupGroup.query.get(group_id)
        if not backup_group:
            return {'success': False, 'message': 'Backup group not found'}
        
        aws_service = AWSService(backup_group.aws_account)
        success_count = 0
        failed_count = 0
        
        for instance in backup_group.instances:
            log_entry = BackupJobLog(
                group_id=group_id,
                instance_id_str=instance.instance_id,
                status='Pending',
                start_time=datetime.utcnow()
            )
            db.session.add(log_entry)
            db.session.commit()
            
            try:
                ec2 = aws_service.session.client('ec2', region_name=instance.region)
                ami_name = f"{backup_group.name}-{instance.instance_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                
                response = ec2.create_image(
                    InstanceId=instance.instance_id,
                    Name=ami_name,
                    Description=f"Backup from group {backup_group.name}",
                    NoReboot=True
                )
                
                log_entry.status = 'Success'
                log_entry.end_time = datetime.utcnow()
                log_entry.ami_id_str = response['ImageId']
                success_count += 1
                
            except Exception as e:
                log_entry.status = 'Failed'
                log_entry.end_time = datetime.utcnow()
                log_entry.message = str(e)
                failed_count += 1
            
            db.session.commit()
        
        if backup_group.policy:
            backup_group.policy.last_run_time = datetime.utcnow()
            db.session.commit()
        
        return {'success': True, 'message': f'Backup completed: {success_count} success, {failed_count} failed'}
        
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


@celery.task
def cleanup_old_backup_logs(days_old=30):
    """Cleanup old backup logs"""
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        deleted_count = BackupJobLog.query.filter(BackupJobLog.start_time < cutoff_date).delete()
        db.session.commit()
        return f"Cleaned up {deleted_count} old backup logs"
    except Exception as e:
        db.session.rollback()
        return f"Cleanup failed: {str(e)}"


@celery.task
def health_check_task():
    """Simple health check task"""
    try:
        account_count = AWSCredentials.query.count()
        instance_count = EC2Instance.query.count()
        return f"Health check OK - {account_count} AWS accounts, {instance_count} instances"
    except Exception as e:
        return f"Health check failed: {str(e)}"

# Add to tasks.py

# --- TASK 1: The "Ticker" that runs every minute ---
# This is the ONLY task that Celery Beat should be calling for backups.

@celery.task(bind=True)
def check_backup_schedules(self):
    """Check for backup policies that need to run and execute them."""
    current_app.logger.info("Scheduler: Checking for due backup jobs...")
    now = datetime.utcnow()
    
    try:
        policies = BackupPolicy.query.filter_by(is_active=True).all()
        
        for policy in policies:
            is_due = False
            
            if policy.last_run_time is None:
                is_due = True
            else:
                # Calculate next_run_time based on interval_unit
                if policy.ami_interval_unit == 'minutes':
                    next_run_time = policy.last_run_time + timedelta(
                        minutes=policy.ami_interval_value
                    )
                elif policy.ami_interval_unit == 'hourly':
                    next_run_time = policy.last_run_time + timedelta(
                        hours=policy.ami_interval_value
                    )
                elif policy.ami_interval_unit == 'days':
                    next_run_time = policy.last_run_time + timedelta(
                        days=policy.ami_interval_value
                    )
                elif policy.ami_interval_unit == 'weekly':
                    next_run_time = policy.last_run_time + timedelta(
                        weeks=policy.ami_interval_value
                    )
                elif policy.ami_interval_unit == 'monthly':
                    # Approximate: add 30 days per month
                    next_run_time = policy.last_run_time + timedelta(
                        days=policy.ami_interval_value * 30
                    )
                elif policy.ami_interval_unit == 'yearly':
                    next_run_time = policy.last_run_time + timedelta(
                        days=policy.ami_interval_value * 365
                    )
                else:
                    current_app.logger.warning(
                        f"Unknown interval unit: {policy.ami_interval_unit}"
                    )
                    continue
                
                if now >= next_run_time:
                    is_due = True
            
            if is_due:
                current_app.logger.info(
                    f"Scheduler: Backup group {policy.group_id} is due. "
                    f"Last run: {policy.last_run_time}, Now: {now}"
                )
                run_backup_task.delay(policy.group_id)
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Scheduler failed: {e}", exc_info=True)

# @celery.task(bind=True)
# def check_backup_schedules(self):
#     """Check for backup policies that need to run and execute them."""
#     current_app.logger.info("Scheduler: Checking for due backup jobs...")
#     now = datetime.utcnow()
    
#     try:
#         policies = BackupPolicy.query.filter_by(is_active=True).all()
        
#         for policy in policies:
#             is_due = False
#             if policy.last_run_time is None:
#                 is_due = True
#             else:
#                 # Check if the policy has the expected fields
#                 if hasattr(policy, 'interval_unit') and hasattr(policy, 'interval_value'):
#                     if policy.interval_unit == 'minutes':
#                         next_run_time = policy.last_run_time + timedelta(minutes=policy.interval_value)
#                     elif policy.interval_unit == 'hours':
#                         next_run_time = policy.last_run_time + timedelta(hours=policy.interval_value)
#                     elif policy.interval_unit == 'days':
#                         next_run_time = policy.last_run_time + timedelta(days=policy.interval_value)
#                     else:
#                         current_app.logger.warning(f"Skipping policy {policy.id}: unknown unit '{policy.interval_unit}'")
#                         continue
#                 else:
#                     # Fallback for old schema - assume daily
#                     next_run_time = policy.last_run_time + timedelta(days=1)
                
#                 if now >= next_run_time:
#                     is_due = True
            
#             if is_due:
#                 current_app.logger.info(f"Scheduler: Backup group {policy.group_id} is due. Launching task.")
#                 run_backup_task.delay(policy.group_id)
                
#                 policy.last_run_time = now
#                 db.session.add(policy)
                
#         db.session.commit()
#     except Exception as e:
#         db.session.rollback()
#         current_app.logger.error(f"Scheduler failed: {e}", exc_info=True)


@celery.task(bind=True, max_retries=3, default_retry_delay=300)
def run_backup_task(self, group_id, policy_id=None, backup_type='ami'):
    """Execute backup for all instances in a backup group."""
    current_app.logger.info(f"Worker: Starting backup for group ID: {group_id}, type: {backup_type}")
    group = db.session.get(BackupGroup, group_id)
    if not group:
        current_app.logger.error(f"Worker: Backup group {group_id} not found. Aborting.")
        return {'success': False, 'message': f'Backup group {group_id} not found.'}

    aws_creds = group.aws_account
    if not aws_creds:
        current_app.logger.error(f"Worker: AWS account for group {group_id} not found. Aborting.")
        return {'success': False, 'message': 'AWS account not found.'}

    try:
        aws_service = AWSService(aws_creds)
        success_count = 0
        
        for instance in group.instances:
            current_app.logger.info(f"Worker: Processing instance {instance.instance_id} in group {group.name}")
            log_entry = BackupJobLog(
                group_id=group.id,
                instance_id_str=instance.instance_id,
                status='Pending',
                start_time=datetime.utcnow()
            )
            db.session.add(log_entry)
            db.session.commit()

            try:
                ec2 = aws_service.session.client('ec2', region_name=instance.region)
                
                if backup_type == 'ami':
                    # Create AMI backup
                    ami_name = f"{group.name}-{instance.instance_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                    response = ec2.create_image(
                        InstanceId=instance.instance_id,
                        Name=ami_name,
                        Description=f"Backup from group {group.name}",
                        NoReboot=True
                    )
                    log_entry.ami_id_str = response['ImageId']
                    
                else:  # snapshot backup
                    # Create snapshots for all volumes
                    snapshots_created = {}
                    volumes = ec2.describe_volumes(
                        Filters=[{'Name': 'attachment.instance-id', 'Values': [instance.instance_id]}]
                    )
                    
                    for volume in volumes.get('Volumes', []):
                        volume_id = volume['VolumeId']
                        description = f"Snapshot of {volume_id} from {instance.instance_id} - {datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                        snapshot = ec2.create_snapshot(
                            VolumeId=volume_id,
                            Description=description
                        )
                        snapshots_created[volume_id] = snapshot['SnapshotId']
                    
                    log_entry.snapshots_created = snapshots_created
                
                log_entry.status = 'Success'
                log_entry.end_time = datetime.utcnow()
                log_entry.instance_type = instance.instance_type
                log_entry.subnet_id_str = instance.subnet_id_str
                log_entry.private_ip = instance.private_ip
                success_count += 1
                
            except Exception as e:
                log_entry.status = 'Failed'
                log_entry.end_time = datetime.utcnow()
                log_entry.message = str(e)
                current_app.logger.error(f"Worker: Failed to back up {instance.instance_id}: {e}")
            
            db.session.commit()
        
        # Update policy last run time
        if group.policy and backup_type == 'ami':
            group.policy.last_run_time = datetime.utcnow()
            db.session.commit()
        
        return {'success': True, 'message': f'Backup completed: {success_count} instances processed'}
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Worker: Group backup failed: {e}", exc_info=True)
        return {'success': False, 'message': str(e)}

# --- TASK 3: The Snapshot Pruner (example) ---
@celery.task(bind=True)
def prune_old_snapshots(self):
    """Finds and deletes snapshots created by this app that are past their retention date."""
    current_app.logger.info("Pruner: Starting daily snapshot pruning task...")
    now = datetime.utcnow().date()
    
    # We need to check snapshots across all accounts
    accounts = AWSCredentials.query.all()
    total_deleted = 0
    
    for account in accounts:
        try:
            aws_service = AWSService(account)
            regions = aws_service._get_all_regions() # Get all regions for this account
            
            for region in regions:
                ec2 = aws_service.session.client('ec2', region_name=region)
                snapshots_to_delete = []
                paginator = ec2.get_paginator('describe_snapshots')
                pages = paginator.paginate(OwnerIds=['self'], Filters=[{'Name': 'tag-key', 'Values': ['DeleteAfter']}])
                
                for page in pages:
                    for snap in page['Snapshots']:
                        delete_after_tag = next((tag['Value'] for tag in snap['Tags'] if tag['Key'] == 'DeleteAfter'), None)
                        if delete_after_tag:
                            try:
                                delete_date = datetime.strptime(delete_after_tag, '%Y-%m-%d').date()
                                if now >= delete_date:
                                    current_app.logger.info(f"Pruning snapshot {snap['SnapshotId']} in {region} (DeleteAfter: {delete_date})")
                                    ec2.delete_snapshot(SnapshotId=snap['SnapshotId'])
                                    total_deleted += 1
                            except (ValueError, ClientError) as e:
                                current_app.logger.warning(f"Could not process or delete snapshot {snap['SnapshotId']}: {e}")
        except Exception as e:
            current_app.logger.error(f"Failed to prune snapshots for account {account.account_name}: {e}", exc_info=True)
            
    return f"Snapshot pruning complete. Deleted {total_deleted} snapshots."



# @celery.task(bind=True)
# def run_backup_task(self, group_id, policy_id=None, backup_type='ami'):
#     """Run backup for a group"""
#     try:
#         group = BackupGroup.query.get(group_id)
#         if not group:
#             return {'success': False, 'message': 'Group not found'}
            
#         instance_count = 0
#         for instance in group.instances:
#             # Create backup job log
#             job = BackupJobLog(
#                 group_id=group_id,
#                 instance_id_str=instance.instance_id,
#                 status='Pending',
#                 start_time=datetime.utcnow()  # Fixed datetime usage
#             )
#             db.session.add(job)
#             db.session.commit()
            
#             # Run backup in AWS
#             try:
#                 aws = AWSService(instance.aws_account)
#                 ec2 = aws.session.client('ec2', region_name=instance.region)
                
#                 if backup_type == 'ami':
#                     # Create AMI backup
#                     ami_name = f"{instance.name or instance.instance_id}-backup-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
#                     response = ec2.create_image(
#                         InstanceId=instance.instance_id, 
#                         Name=ami_name,
#                         NoReboot=True
#                     )
                    
#                     job.ami_id_str = response['ImageId']
#                 else:
#                     # Create snapshot backup
#                     snapshots = []
#                     # Get instance volumes
#                     volumes = ec2.describe_volumes(
#                         Filters=[{'Name': 'attachment.instance-id', 'Values': [instance.instance_id]}]
#                     )
                    
#                     for volume in volumes.get('Volumes', []):
#                         volume_id = volume['VolumeId']
#                         description = f"Snapshot of {volume_id} from {instance.instance_id} - {datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                        
#                         snapshot = ec2.create_snapshot(
#                             VolumeId=volume_id,
#                             Description=description
#                         )
                        
#                         snapshots.append(snapshot['SnapshotId'])
                    
#                     job.snapshots_created = snapshots
                
#                 # Update job status
#                 job.status = 'Success'
#                 job.end_time = datetime.utcnow()  # Fixed datetime usage
#                 db.session.commit()
#                 instance_count += 1
                
#             except Exception as e:
#                 job.status = 'Failed'
#                 job.message = str(e)
#                 job.end_time = datetime.utcnow()  # Fixed datetime usage
#                 db.session.commit()
#                 current_app.logger.error(f"Backup failed for {instance.instance_id}: {e}")
                
#         # Update policy last run time if specified
#         if policy_id:
#             policy = BackupPolicy.query.get(policy_id)
#             if policy:
#                 if backup_type == 'ami':
#                     policy.last_ami_time = datetime.utcnow()  # Fixed datetime usage
#                 else:
#                     policy.last_snapshot_time = datetime.utcnow()  # Fixed datetime usage
#                 db.session.commit()
                
#         return {'success': True, 'message': f'Backup completed for {instance_count} instances'}
        
#     except Exception as e:
#         current_app.logger.error(f"Group backup failed: {e}", exc_info=True)
#         return {'success': False, 'message': str(e)}


@celery.task
def sync_all_accounts():
    """Sync all accounts daily"""
    current_app.logger.info("Starting scheduled sync for all accounts")
    accounts = AWSCredentials.query.all()
    for account in accounts:
        sync_inventory_task.delay(account.id)
    return f"Scheduled sync for {len(accounts)} accounts"

@celery.task
def cleanup_old_backups():
    """Clean up old backups based on retention policies"""
    current_app.logger.info("Starting scheduled cleanup of old backups")
    policies = BackupPolicy.query.filter_by(is_active=True).all()
    cleanup_count = 0
    
    for policy in policies:
        # Calculate the retention date cutoff
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=policy.retention_days)
        
        # Find old backup logs with successful AMI creation
        old_jobs = BackupJobLog.query.filter(
            BackupJobLog.group_id == policy.group_id,
            BackupJobLog.status == 'Success',
            BackupJobLog.start_time < cutoff_date,
            BackupJobLog.ami_id_str != None
        ).all()
        
        for job in old_jobs:
            try:
                # Get the AWS account
                account = AWSCredentials.query.join(BackupGroup).filter(BackupGroup.id == job.group_id).first()
                if not account:
                    continue
                
                aws = AWSService(account)
                ec2 = aws.session.client('ec2', region_name=job.region if job.region else account.default_region)
                
                # Deregister AMI
                if job.ami_id_str:
                    ec2.deregister_image(ImageId=job.ami_id_str)
                    cleanup_count += 1
                
                # Delete associated snapshots
                if job.snapshots_created:
                    for snapshot_id in job.snapshots_created:
                        ec2.delete_snapshot(SnapshotId=snapshot_id)
                        
                # Mark job as cleaned up
                job.status = 'Cleaned'
                db.session.commit()
                
            except Exception as e:
                current_app.logger.error(f"Error cleaning up backup {job.id}: {e}")
    
    return f"Cleaned up {cleanup_count} old backups"