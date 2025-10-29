# File: app/services/restore_service.py
"""
Restoration Service - Automated restoration from both AMI and snapshot backups
"""
import boto3
import time
from flask import current_app
from app import db
from app.models import BackupJobLog, AWSCredentials, EC2Instance
from app.services.aws_service import AWSService


class RestoreService:
    """
    Handles automated instance restoration from backups
    """
    
    def __init__(self, aws_credentials: AWSCredentials):
        self.credentials = aws_credentials
        self.aws_service = AWSService(aws_credentials)
        self.session = self.aws_service.session
    
    def restore_from_backup(self, backup_log_id: int, options: dict = None):
        """
        Main restoration function - handles both AMI and snapshot backups
        
        Args:
            backup_log_id: ID of BackupJobLog to restore from
            options: Optional dict with:
                - target_vpc: Override VPC
                - target_subnet: Override subnet
                - instance_type: Override instance type
                - assign_elastic_ip: Assign new EIP
                - new_key_pair: Use different key pair
        """
        log = BackupJobLog.query.get(backup_log_id)
        if not log:
            raise ValueError(f"Backup log {backup_log_id} not found")
        
        if log.status != 'Success':
            raise ValueError(f"Cannot restore from failed backup")
        
        options = options or {}
        
        if log.backup_type == 'ami':
            return self._restore_from_ami(log, options)
        else:  # snapshot
            return self._restore_from_snapshots(log, options)
    
    def _restore_from_ami(self, log: BackupJobLog, options: dict):
        """
        Simple AMI restoration - launch instance from AMI
        """
        ec2_client = self.session.client('ec2', region_name=log.region)
        
        try:
            # Prepare launch parameters
            launch_params = self._prepare_launch_params(log, options)
            launch_params['ImageId'] = log.ami_id_str
            
            current_app.logger.info(f"Launching instance from AMI {log.ami_id_str}")
            
            # Launch instance
            response = ec2_client.run_instances(**launch_params)
            new_instance_id = response['Instances'][0]['InstanceId']
            
            # Wait for instance to be running
            waiter = ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[new_instance_id])
            
            # Apply tags
            ec2_client.create_tags(
                Resources=[new_instance_id],
                Tags=[
                    {'Key': 'Name', 'Value': f"Restored-{log.instance_id_str}"},
                    {'Key': 'RestoredFrom', 'Value': log.instance_id_str},
                    {'Key': 'RestoreTime', 'Value': time.strftime('%Y-%m-%d %H:%M:%S')},
                    {'Key': 'BackupLogId', 'Value': str(log.id)}
                ] + (log.tags or [])
            )
            
            # Assign Elastic IP if requested
            if options.get('assign_elastic_ip'):
                self._assign_elastic_ip(ec2_client, new_instance_id)
            
            current_app.logger.info(f"Successfully restored instance: {new_instance_id}")
            
            return {
                'success': True,
                'instance_id': new_instance_id,
                'restore_method': 'ami',
                'message': f'Instance restored from AMI {log.ami_id_str}'
            }
            
        except Exception as e:
            current_app.logger.error(f"AMI restoration failed: {e}", exc_info=True)
            raise
    
    def _restore_from_snapshots(self, log: BackupJobLog, options: dict):
        """
        Complex snapshot restoration - launch from parent AMI and swap volumes
        This is the AUTOMATED MAGIC that makes hybrid backups seamless
        """
        ec2_client = self.session.client('ec2', region_name=log.region)
        
        try:
            # Step 1: Launch from parent AMI
            current_app.logger.info(f"Step 1: Launching from parent AMI {log.parent_ami_id}")
            
            launch_params = self._prepare_launch_params(log, options)
            launch_params['ImageId'] = log.parent_ami_id
            
            response = ec2_client.run_instances(**launch_params)
            temp_instance_id = response['Instances'][0]['InstanceId']
            
            # Wait for running
            waiter = ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[temp_instance_id])
            
            current_app.logger.info(f"Step 2: Instance {temp_instance_id} launched, now stopping for volume swap")
            
            # Step 2: Stop instance for volume swap
            ec2_client.stop_instances(InstanceIds=[temp_instance_id])
            waiter = ec2_client.get_waiter('instance_stopped')
            waiter.wait(InstanceIds=[temp_instance_id])
            
            # Step 3: Swap volumes with snapshot-based volumes
            current_app.logger.info(f"Step 3: Swapping volumes with snapshots")
            
            for snapshot_info in log.snapshots_created:
                snapshot_id = snapshot_info['snapshot_id']
                device_name = snapshot_info['device_name']
                
                current_app.logger.info(f"  Processing {device_name} from {snapshot_id}")
                
                # Get current volume attached to this device
                instance_details = ec2_client.describe_instances(InstanceIds=[temp_instance_id])
                current_volumes = instance_details['Reservations'][0]['Instances'][0].get('BlockDeviceMappings', [])
                
                old_volume_id = None
                for bdm in current_volumes:
                    if bdm['DeviceName'] == device_name:
                        old_volume_id = bdm['Ebs']['VolumeId']
                        break
                
                if old_volume_id:
                    # Detach old volume
                    current_app.logger.info(f"    Detaching old volume {old_volume_id}")
                    ec2_client.detach_volume(
                        VolumeId=old_volume_id,
                        InstanceId=temp_instance_id,
                        Device=device_name
                    )
                    
                    # Wait for detachment
                    self._wait_for_volume_state(ec2_client, old_volume_id, 'available')
                
                # Create new volume from snapshot
                current_app.logger.info(f"    Creating volume from snapshot {snapshot_id}")
                new_volume = ec2_client.create_volume(
                    SnapshotId=snapshot_id,
                    AvailabilityZone=log.availability_zone,
                    VolumeType=snapshot_info.get('volume_type', 'gp3'),
                    TagSpecifications=[{
                        'ResourceType': 'volume',
                        'Tags': [
                            {'Key': 'Name', 'Value': f"Restored-{device_name}"},
                            {'Key': 'RestoredFrom', 'Value': snapshot_id}
                        ]
                    }]
                )
                new_volume_id = new_volume['VolumeId']
                
                # Wait for volume to be available
                self._wait_for_volume_state(ec2_client, new_volume_id, 'available')
                
                # Attach new volume
                current_app.logger.info(f"    Attaching new volume {new_volume_id} to {device_name}")
                ec2_client.attach_volume(
                    VolumeId=new_volume_id,
                    InstanceId=temp_instance_id,
                    Device=device_name
                )
                
                # Wait for attachment
                self._wait_for_volume_state(ec2_client, new_volume_id, 'in-use')
                
                # Delete old volume
                if old_volume_id:
                    current_app.logger.info(f"    Deleting old volume {old_volume_id}")
                    try:
                        ec2_client.delete_volume(VolumeId=old_volume_id)
                    except:
                        pass  # Don't fail if deletion fails
            
            # Step 4: Start instance with restored volumes
            current_app.logger.info(f"Step 4: Starting instance with restored data")
            ec2_client.start_instances(InstanceIds=[temp_instance_id])
            waiter = ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[temp_instance_id])
            
            # Apply tags
            ec2_client.create_tags(
                Resources=[temp_instance_id],
                Tags=[
                    {'Key': 'Name', 'Value': f"Restored-{log.instance_id_str}"},
                    {'Key': 'RestoredFrom', 'Value': log.instance_id_str},
                    {'Key': 'RestoreMethod', 'Value': 'snapshot-swap'},
                    {'Key': 'RestoreTime', 'Value': time.strftime('%Y-%m-%d %H:%M:%S')},
                    {'Key': 'BackupLogId', 'Value': str(log.id)}
                ] + (log.tags or [])
            )
            
            # Assign Elastic IP if requested
            if options.get('assign_elastic_ip'):
                self._assign_elastic_ip(ec2_client, temp_instance_id)
            
            current_app.logger.info(f"Successfully restored instance: {temp_instance_id}")
            
            return {
                'success': True,
                'instance_id': temp_instance_id,
                'restore_method': 'snapshot-swap',
                'message': f'Instance restored from snapshots (parent AMI: {log.parent_ami_id})'
            }
            
        except Exception as e:
            current_app.logger.error(f"Snapshot restoration failed: {e}", exc_info=True)
            # Clean up if possible
            try:
                if 'temp_instance_id' in locals():
                    ec2_client.terminate_instances(InstanceIds=[temp_instance_id])
            except:
                pass
            raise
    
    def _prepare_launch_params(self, log: BackupJobLog, options: dict):
        """
        Prepare common EC2 launch parameters from backup metadata
        """
        params = {
            'InstanceType': options.get('instance_type') or log.instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'SubnetId': options.get('target_subnet') or log.subnet_id_str,
            'SecurityGroupIds': log.security_group_ids or []
        }
        
        # Key pair
        if options.get('new_key_pair'):
            params['KeyName'] = options['new_key_pair']
        elif log.key_pair_name:
            params['KeyName'] = log.key_pair_name
        
        # IAM role
        if log.iam_role_arn:
            params['IamInstanceProfile'] = {'Arn': log.iam_role_arn}
        
        # User data
        if log.user_data:
            params['UserData'] = log.user_data
        
        # Private IP (if in same subnet)
        if not options.get('target_subnet') and log.private_ip:
            params['PrivateIpAddress'] = log.private_ip
        
        return params
    
    def _wait_for_volume_state(self, ec2_client, volume_id: str, desired_state: str, max_attempts: int = 40):
        """Wait for volume to reach desired state"""
        for attempt in range(max_attempts):
            response = ec2_client.describe_volumes(VolumeIds=[volume_id])
            current_state = response['Volumes'][0]['State']
            
            if current_state == desired_state:
                return True
            
            if current_state == 'error':
                raise Exception(f"Volume {volume_id} entered error state")
            
            time.sleep(5)
        
        raise Exception(f"Volume {volume_id} did not reach {desired_state} state in time")
    
    def _assign_elastic_ip(self, ec2_client, instance_id: str):
        """Allocate and assign new Elastic IP"""
        try:
            # Allocate EIP
            eip_response = ec2_client.allocate_address(Domain='vpc')
            allocation_id = eip_response['AllocationId']
            
            # Associate with instance
            ec2_client.associate_address(
                InstanceId=instance_id,
                AllocationId=allocation_id
            )
            
            current_app.logger.info(f"Assigned Elastic IP {eip_response['PublicIp']} to {instance_id}")
            
        except Exception as e:
            current_app.logger.error(f"Failed to assign Elastic IP: {e}")