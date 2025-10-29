"""
app/dashboard/routes.py
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app import db
from app.models import (
    AWSCredentials, EC2Instance, VPC, Subnet, SecurityGroup, AMI, Snapshot,
    BackupGroup, BackupPolicy, BackupJobLog, instance_backup_group_association
)
from app.services.security_service import SecurityService
from app.tasks import sync_inventory_task
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from app.services.aws_service import AWSService

bp = Blueprint('dashboard', __name__)


# ========== DASHBOARD PAGES ==========

@bp.route('/')
@login_required
def index():
    """Main dashboard home page"""
    aws_accounts = AWSCredentials.query.filter_by(user_id=current_user.id).all()
    
    stats = {
        'instance_count': EC2Instance.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).count(),
        'snapshot_count': Snapshot.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).count(),
        'vpc_count': VPC.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).count(),
        'sg_count': SecurityGroup.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).count(),
        'ami_count': AMI.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).count(),
        'subnet_count': Subnet.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).count()
    }
    
    return render_template('dashboard/home.html', aws_accounts=aws_accounts, stats=stats)


@bp.route('/aws-accounts')
@login_required
def aws_accounts():
    """AWS Accounts management page"""
    aws_accounts = AWSCredentials.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard/accounts.html', aws_accounts=aws_accounts)


# ========== ACCOUNT MANAGEMENT ==========

@bp.route('/add-account', methods=['POST'])
@login_required
def add_account():
    """Add new AWS account"""
    try:
        account_name = request.form.get('account_name', '').strip()
        auth_type = request.form.get('auth_type', '').strip()
        default_region = request.form.get('default_region', '').strip()
        
        if not account_name:
            flash('Account name is required', 'error')
            return redirect(url_for('dashboard.aws_accounts'))
        
        if auth_type not in ['access_key', 'iam_role']:
            flash('Invalid authentication type', 'error')
            return redirect(url_for('dashboard.aws_accounts'))
        
        existing = AWSCredentials.query.filter_by(
            account_name=account_name,
            user_id=current_user.id
        ).first()
        
        if existing:
            flash(f'Account "{account_name}" already exists', 'error')
            return redirect(url_for('dashboard.aws_accounts'))
        
        security_service = SecurityService()
        
        new_account = AWSCredentials(
            account_name=account_name,
            auth_type=auth_type,
            user_id=current_user.id,
            default_region=default_region if default_region else None,
            last_sync_status='Never Synced'
        )
        
        if auth_type == 'access_key':
            aws_access_key_id = request.form.get('aws_access_key_id', '').strip()
            aws_secret_access_key = request.form.get('aws_secret_access_key', '').strip()
            
            if not aws_access_key_id or not aws_secret_access_key:
                flash('Access Key ID and Secret Key are required', 'error')
                return redirect(url_for('dashboard.aws_accounts'))
            
            new_account.aws_access_key_id = aws_access_key_id
            new_account.encrypted_aws_secret_access_key = security_service.encrypt_data(aws_secret_access_key)
            
        elif auth_type == 'iam_role':
            role_arn = request.form.get('role_arn', '').strip()
            
            if not role_arn:
                flash('IAM Role ARN is required', 'error')
                return redirect(url_for('dashboard.aws_accounts'))
            
            new_account.role_arn = role_arn
        
        db.session.add(new_account)
        db.session.commit()
        
        flash(f'Account "{account_name}" added successfully!', 'success')
        
    except IntegrityError:
        db.session.rollback()
        flash('Account name must be unique', 'error')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding account: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.aws_accounts'))


@bp.route('/sync-account/<int:account_id>', methods=['POST'])
@login_required
def sync_account(account_id):
    """Trigger sync for an account"""
    account = AWSCredentials.query.filter_by(
        id=account_id,
        user_id=current_user.id
    ).first_or_404()
    
    if account.last_sync_status == "Syncing in background...":
        flash('Sync already in progress', 'warning')
    else:
        try:
            sync_inventory_task.delay(account_id)
            flash(f'Sync started for {account.account_name}', 'success')
        except Exception as e:
            flash(f'Error starting sync: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.aws_accounts'))


@bp.route('/delete-account/<int:account_id>', methods=['POST'])
@login_required
def delete_account(account_id):
    """Delete an AWS account"""
    account = AWSCredentials.query.filter_by(
        id=account_id,
        user_id=current_user.id
    ).first_or_404()
    
    try:
        db.session.delete(account)
        db.session.commit()
        flash(f'Account "{account.account_name}" deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting account: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.aws_accounts'))


# ========== CRITICAL API ROUTES FOR INSTANCE MANAGEMENT ==========

@bp.route('/api/instances', methods=['GET'])
@login_required
def get_instances():
    """Get all EC2 instances for current user"""
    try:
        instances = db.session.query(EC2Instance, AWSCredentials.account_name) \
            .join(AWSCredentials, EC2Instance.aws_account_id == AWSCredentials.id) \
            .filter(AWSCredentials.user_id == current_user.id).all()
        
        data = [{
            'instance_id': inst.instance_id,
            'name': inst.name or 'N/A',
            'state': inst.state,
            'instance_type': inst.instance_type or 'N/A',
            'account_name': account_name,
            'region': inst.region,
            'public_ip': inst.public_ip or 'N/A',
            'private_ip': inst.private_ip or 'N/A'
        } for inst, account_name in instances]
        
        return jsonify({'success': True, 'total': len(data), 'data': data})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/instance/<instance_id>/start', methods=['POST'])
@login_required
def start_instance(instance_id):
    """Start EC2 instance"""
    try:
        inst = EC2Instance.query.filter_by(instance_id=instance_id) \
            .join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).first_or_404()
        
        ec2 = AWSService(inst.aws_account).session.client('ec2', region_name=inst.region)
        ec2.start_instances(InstanceIds=[instance_id])
        
        # Update state in database immediately
        inst.state = 'pending'
        db.session.commit()
        
        # Trigger async refresh - START takes 10-20 seconds to reach 'running'
        try:
            from app.tasks import refresh_single_instance
            refresh_single_instance.apply_async((inst.aws_account_id, instance_id), countdown=15)
        except:
            pass
        
        return jsonify({'success': True, 'message': f'Starting {instance_id}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/instance/<instance_id>/stop', methods=['POST'])
@login_required
def stop_instance(instance_id):
    """Stop EC2 instance"""
    try:
        inst = EC2Instance.query.filter_by(instance_id=instance_id) \
            .join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).first_or_404()
        
        ec2 = AWSService(inst.aws_account).session.client('ec2', region_name=inst.region)
        ec2.stop_instances(InstanceIds=[instance_id])
        
        # Update state in database immediately
        inst.state = 'stopping'
        db.session.commit()
        
        # Trigger async refresh - STOP takes 10-30 seconds to reach 'stopped'
        try:
            from app.tasks import refresh_single_instance
            refresh_single_instance.apply_async((inst.aws_account_id, instance_id), countdown=20)
        except:
            pass
        
        return jsonify({'success': True, 'message': f'Stopping {instance_id}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/instance/<instance_id>/backup', methods=['POST'])
@login_required
def backup_instance(instance_id):
    """Create AMI backup of instance"""
    try:
        inst = EC2Instance.query.filter_by(instance_id=instance_id) \
            .join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).first_or_404()
        
        ec2 = AWSService(inst.aws_account).session.client('ec2', region_name=inst.region)
        ami_name = f"{inst.name or instance_id}-backup-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        response = ec2.create_image(InstanceId=instance_id, Name=ami_name, NoReboot=True)
        
        return jsonify({'success': True, 'message': f'AMI Created: {response["ImageId"]}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/instance/<instance_id>/reboot', methods=['POST'])
@login_required
def reboot_instance(instance_id):
    """Reboot EC2 instance"""
    try:
        inst = EC2Instance.query.filter_by(instance_id=instance_id) \
            .join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).first_or_404()
        
        ec2 = AWSService(inst.aws_account).session.client('ec2', region_name=inst.region)
        ec2.reboot_instances(InstanceIds=[instance_id])
        
        # Update state in database immediately
        inst.state = 'rebooting'
        db.session.commit()
        
        # Trigger async refresh - REBOOT takes 30-60 seconds to complete
        try:
            from app.tasks import refresh_single_instance
            refresh_single_instance.apply_async((inst.aws_account_id, instance_id), countdown=40)
        except:
            pass
        
        return jsonify({'success': True, 'message': f'Rebooting {instance_id}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# ========== PAGE ROUTES ==========

@bp.route('/ec2')
@login_required
def ec2_page():
    """EC2 Instances page"""
    aws_accounts = AWSCredentials.query.filter_by(user_id=current_user.id).all()
    stats = {
        'instance_count': EC2Instance.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id).count(),
        'running_count': EC2Instance.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id, EC2Instance.state == 'running').count(),
        'stopped_count': EC2Instance.query.join(AWSCredentials).filter(AWSCredentials.user_id == current_user.id, EC2Instance.state == 'stopped').count(),
    }
    return render_template('dashboard/ec2.html', aws_accounts=aws_accounts, stats=stats)


@bp.route('/backups/groups')
@login_required
def backup_groups():
    """Backup Groups page"""
    aws_accounts = AWSCredentials.query.filter_by(user_id=current_user.id).all()
    
    # Fetch real backup groups with their policies and instances
    from app.models import BackupGroup
    backup_groups = BackupGroup.query.join(AWSCredentials)\
        .filter(AWSCredentials.user_id == current_user.id)\
        .order_by(BackupGroup.name).all()
    
    # Get all instances for the create group modal
    instances = EC2Instance.query.join(AWSCredentials)\
        .filter(AWSCredentials.user_id == current_user.id)\
        .order_by(EC2Instance.name).all()
    
    return render_template('dashboard/backups/groups.html', 
                         aws_accounts=aws_accounts,
                         backup_groups=backup_groups,
                         instances=instances)



@bp.route('/backups/schedules')
@login_required
def backup_schedules():
    """Backup Schedules page"""
    aws_accounts = AWSCredentials.query.filter_by(user_id=current_user.id).all()
    
    # Load backup policies with eager loading of group relationship
    backup_policies = BackupPolicy.query\
        .join(BackupPolicy.group)\
        .join(BackupGroup.aws_account)\
        .filter(AWSCredentials.user_id == current_user.id)\
        .options(db.joinedload(BackupPolicy.group))\
        .all()
    
    # Count stats
    stats = {
        'active_count': sum(1 for policy in backup_policies if policy.is_active),
        'paused_count': sum(1 for policy in backup_policies if not policy.is_active),
        'ami_today_count': db.session.query(BackupJobLog).filter(
            BackupJobLog.ami_id_str != None,
            BackupJobLog.start_time >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        ).count(),
        'snapshot_today_count': db.session.query(BackupJobLog).filter(
            BackupJobLog.snapshots_created != None,
            BackupJobLog.ami_id_str == None,
            BackupJobLog.start_time >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        ).count()
    }
    
    def calculate_next_run(last_run, interval_value, interval_unit):
        if not last_run:
            return "Not run yet"
        
        # Calculate next run based on interval
        if interval_unit == 'minutes':
            next_run = last_run + datetime.timedelta(minutes=interval_value)
        elif interval_unit == 'hours':
            next_run = last_run + datetime.timedelta(hours=interval_value)
        elif interval_unit == 'days':
            next_run = last_run + datetime.timedelta(days=interval_value)
        else:
            return "Unknown"
        
        # Format the next run time
        now = datetime.utcnow()
        if next_run < now:
            return "Overdue"
        
        diff = next_run - now
        if diff.days > 0:
            return f"in {diff.days} days"
        elif diff.seconds > 3600:
            return f"in {diff.seconds // 3600} hours"
        else:
            return f"in {diff.seconds // 60} minutes"
    
    return render_template(
        'dashboard/backups/schedules.html',
        aws_accounts=aws_accounts,
        stats=stats,
        backup_policies=backup_policies,
        calculate_next_run=calculate_next_run
    )


@bp.route('/backups/history')
@login_required
def backup_history():
    """Backup History page"""
    from app.models import BackupGroup, BackupPolicy, BackupJobLog
    from datetime import datetime, timedelta
    
    # Calculate stats for last 7 days
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    # Get all backup logs for the user
    user_logs = BackupJobLog.query.join(BackupGroup).join(AWSCredentials)\
        .filter(AWSCredentials.user_id == current_user.id)
    
    # Calculate real stats
    stats = {
        'success_count': user_logs.filter(BackupJobLog.status == 'Success',
                                         BackupJobLog.start_time >= seven_days_ago).count(),
        'failed_count': user_logs.filter(BackupJobLog.status == 'Failed',
                                        BackupJobLog.start_time >= seven_days_ago).count(),
        'pending_count': user_logs.filter(BackupJobLog.status == 'Pending').count(),
        'total_count': user_logs.count()
    }
    
    # Get recent backup history logs with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    history_logs = user_logs.order_by(BackupJobLog.start_time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('dashboard/backups/history.html', 
                         stats=stats,
                         history_logs=history_logs)


# ========== BACKUP MANAGEMENT ROUTES ==========

@bp.route('/backup-groups/create', methods=['POST'])
@login_required
def create_backup_group():
    """Create a new backup group with instances and policy"""
    from app.models import BackupGroup, BackupPolicy
    
    try:
        # Get form data
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        instance_ids = request.form.getlist('instance_ids')
        backup_strategy = request.form.get('backup_strategy', 'hybrid')
        
        # Get the first AWS account for this user (or let user select)
        aws_account = AWSCredentials.query.filter_by(user_id=current_user.id).first()
        if not aws_account:
            flash('Please add an AWS account first', 'error')
            return redirect(url_for('dashboard.backup_groups'))
        
        # Create backup group
        backup_group = BackupGroup(
            name=name,
            aws_account_id=aws_account.id
        )
        db.session.add(backup_group)
        db.session.flush()  # Get the ID
        
        # Add instances to the group
        for instance_id in instance_ids:
            instance = EC2Instance.query.get(instance_id)
            if instance and instance.aws_account.user_id == current_user.id:
                backup_group.instances.append(instance)
        
        # Create backup policy
        policy = BackupPolicy(
            group_id=backup_group.id,
            backup_strategy=backup_strategy,
            ami_interval_value=int(request.form.get('ami_interval_value', 1)),
            ami_interval_unit=request.form.get('ami_interval_unit', 'days'),
            snapshot_interval_value=int(request.form.get('snapshot_interval_value', 15)),
            snapshot_interval_unit=request.form.get('snapshot_interval_unit', 'minutes'),
            is_active=request.form.get('is_active') == 'on'
        )
        
        # Set retention policy
        retention_type = request.form.get('retention_type', 'days')
        if retention_type == 'days':
            policy.retention_days = int(request.form.get('retention_days', 7))
        else:
            policy.retention_count = int(request.form.get('retention_count', 10))
        
        db.session.add(policy)
        db.session.commit()
        
        flash(f'Backup group "{name}" created successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating backup group: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.backup_groups'))


@bp.route('/backup-groups/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_backup_group(group_id):
    """Edit an existing backup group"""
    from app.models import BackupGroup, BackupPolicy
    
    backup_group = BackupGroup.query.join(AWSCredentials)\
        .filter(BackupGroup.id == group_id, AWSCredentials.user_id == current_user.id).first_or_404()
    
    if request.method == 'POST':
        try:
            # Update group details
            backup_group.name = request.form.get('name', backup_group.name).strip()
            
            # Update policy if it exists
            if backup_group.policy:
                policy = backup_group.policy
                policy.backup_strategy = request.form.get('backup_strategy', policy.backup_strategy)
                policy.ami_interval_value = int(request.form.get('ami_interval_value', policy.ami_interval_value))
                policy.ami_interval_unit = request.form.get('ami_interval_unit', policy.ami_interval_unit)
                policy.snapshot_interval_value = int(request.form.get('snapshot_interval_value', policy.snapshot_interval_value))
                policy.snapshot_interval_unit = request.form.get('snapshot_interval_unit', policy.snapshot_interval_unit)
                policy.is_active = request.form.get('is_active') == 'on'
                
                # Update retention
                retention_type = request.form.get('retention_type', 'days')
                if retention_type == 'days':
                    policy.retention_days = int(request.form.get('retention_days', 7))
                    policy.retention_count = None
                else:
                    policy.retention_count = int(request.form.get('retention_count', 10))
                    policy.retention_days = None
            
            db.session.commit()
            flash(f'Backup group "{backup_group.name}" updated successfully!', 'success')
            return redirect(url_for('dashboard.backup_groups'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating backup group: {str(e)}', 'error')
    
    # For GET request, render edit template
    instances = EC2Instance.query.join(AWSCredentials)\
        .filter(AWSCredentials.user_id == current_user.id).all()
    
    return render_template('dashboard/backups/edit_group.html',
                         backup_group=backup_group,
                         instances=instances)


@bp.route('/backup-groups/<int:group_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_backup_group(group_id):
    """Delete a backup group"""
    from app.models import BackupGroup
    
    backup_group = BackupGroup.query.join(AWSCredentials)\
        .filter(BackupGroup.id == group_id, AWSCredentials.user_id == current_user.id).first_or_404()
    
    try:
        name = backup_group.name
        db.session.delete(backup_group)
        db.session.commit()
        flash(f'Backup group "{name}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting backup group: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.backup_groups'))


# @bp.route('/backup-groups/<int:group_id>/run-now', methods=['POST'])
# @login_required
# def run_backup_now(group_id):
#     """Run backup now for a specific group"""
#     from app.models import BackupGroup
#     from app.tasks import execute_backup_group_task
    
#     backup_group = BackupGroup.query.join(AWSCredentials)\
#         .filter(BackupGroup.id == group_id, AWSCredentials.user_id == current_user.id).first_or_404()
    
#     try:
#         # Trigger the backup task
#         execute_backup_group_task.delay(group_id)
#         flash(f'Backup started for group "{backup_group.name}"', 'success')
#     except Exception as e:
#         flash(f'Error starting backup: {str(e)}', 'error')
    
#     return redirect(url_for('dashboard.backup_groups'))


# @bp.route('/backup-groups/run-now', methods=['POST'])
# @login_required
# def run_backup_now_modal():
#     """Run backup from modal (when group_id is in form data)"""
#     group_id = request.form.get('group_id', type=int)
#     if group_id:
#         return run_backup_now(group_id)
#     else:
#         flash('Invalid backup group', 'error')
#         return redirect(url_for('dashboard.backup_groups'))


@bp.route('/backup-schedules/<int:policy_id>/pause', methods=['GET', 'POST'])
@login_required
def pause_backup_schedule(policy_id):
    """Pause a backup schedule"""
    from app.models import BackupPolicy, BackupGroup
    
    policy = BackupPolicy.query.join(BackupGroup).join(AWSCredentials)\
        .filter(BackupPolicy.id == policy_id, AWSCredentials.user_id == current_user.id).first_or_404()
    
    try:
        policy.is_active = False
        db.session.commit()
        flash(f'Schedule paused for group "{policy.group.name}"', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error pausing schedule: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.backup_schedules'))


@bp.route('/backup-schedules/<int:policy_id>/resume', methods=['GET', 'POST'])
@login_required
def resume_backup_schedule(policy_id):
    """Resume a backup schedule"""
    from app.models import BackupPolicy, BackupGroup
    
    policy = BackupPolicy.query.join(BackupGroup).join(AWSCredentials)\
        .filter(BackupPolicy.id == policy_id, AWSCredentials.user_id == current_user.id).first_or_404()
    
    try:
        policy.is_active = True
        db.session.commit()
        flash(f'Schedule resumed for group "{policy.group.name}"', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resuming schedule: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.backup_schedules'))

@bp.route('/backups/run-now/<int:group_id>', methods=['POST'])
@login_required
def run_backup_now(group_id):
    """Run backup job now for a group from the schedules page"""
    try:
        group = BackupGroup.query.filter_by(id=group_id).join(AWSCredentials).filter(
            AWSCredentials.user_id == current_user.id
        ).first_or_404()
        
        # Get policy ID and backup type
        policy_id = request.form.get('policy_id')
        backup_type = request.form.get('backup_type', 'ami')
        
        # Queue the backup task
        from app.tasks import run_backup_task
        task = run_backup_task.delay(group_id, policy_id, backup_type)
        
        flash(f'Backup job for "{group.name}" has been initiated', 'success')
        
    except Exception as e:
        flash(f'Error initiating backup: {str(e)}', 'error')
        
    return redirect(url_for('dashboard.backup_schedules'))

# Change this function name to avoid conflicts
@bp.route('/backup-groups/run-now', methods=['POST'])
@login_required
def run_backup_now_from_groups():  # Renamed from run_backup_now_modal
    """Run backup job now for a group from the groups page"""
    try:
        group_id = request.form.get('group_id', type=int)
        group = BackupGroup.query.filter_by(id=group_id).join(AWSCredentials).filter(
            AWSCredentials.user_id == current_user.id
        ).first_or_404()
        
        # Get backup type
        backup_type = request.form.get('backup_type', 'ami')
        
        # Queue the backup task
        from app.tasks import run_backup_task
        task = run_backup_task.delay(group_id, None, backup_type)
        
        flash(f'Backup job for "{group.name}" has been initiated', 'success')
        
    except Exception as e:
        flash(f'Error initiating backup: {str(e)}', 'error')
        
    # Return to schedules page
    return redirect(url_for('dashboard.backup_schedules'))
