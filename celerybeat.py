#!/usr/bin/env python3
"""
Celery Beat Scheduler for AWS Dashboard
This file sets up the Celery Beat scheduler for periodic backup tasks.
Usage: celery -A celerybeat.celery beat --loglevel=info
"""
import os
from celery import Celery
from app import create_app

# Create the Flask app context
flask_app = create_app()

def make_celery(app):
    """
    Configure and create a Celery instance for Beat scheduling.
    """
    celery = Celery(
        app.import_name,
        backend=app.config.get('result_backend'),
        broker=app.config.get('broker_url')
    )
    
    # Update Celery configuration
    celery.conf.update(
        broker_url=app.config.get('broker_url'),
        result_backend=app.config.get('result_backend'),
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        beat_schedule_filename='celerybeat-schedule',
    )

    # Configure periodic backup tasks
    celery.conf.beat_schedule = {
        
        'check-scheduled-backups': {
            'task': 'app.tasks.check_and_execute_scheduled_backups',
            'schedule': 60.0,  # Check every minute
            'options': {'expires': 50}
       },
        # Example: Auto-sync inventory every 30 minutes
        'auto-sync-inventory': {
            'task': 'app.tasks.sync_inventory_task',
            'schedule': 1800.0,  # 30 minutes
            'kwargs': {'account_id': 1},  # You can make this dynamic
            'options': {'expires': 60}
        },
        
        # Example: Cleanup old backup logs daily at 2 AM
        'cleanup-backup-logs': {
            'task': 'app.tasks.cleanup_old_backup_logs',
            'schedule': 86400.0,  # Daily
            'kwargs': {'days_old': 30},
            'options': {'expires': 300}
        },
        
        # Example: Health check every 5 minutes
        'health-check': {
            'task': 'app.tasks.health_check_task',
            'schedule': 300.0,  # 5 minutes
            'options': {'expires': 30}
        },
    }

    class ContextTask(celery.Task):
        """Ensure Celery tasks run inside Flask app context"""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

# Create and expose Celery instance
celery = make_celery(flask_app)

# Add these task stubs to your tasks.py if they don't exist
@celery.task
def cleanup_old_backup_logs(days_old=30):
    """Cleanup old backup logs"""
    from datetime import datetime, timedelta
    from app.models import BackupJobLog
    from app import db
    
    cutoff_date = datetime.utcnow() - timedelta(days=days_old)
    deleted_count = BackupJobLog.query.filter(
        BackupJobLog.start_time < cutoff_date
    ).delete()
    
    db.session.commit()
    return f"Cleaned up {deleted_count} old backup logs"

@celery.task
def health_check_task():
    """Simple health check task"""
    from app.models import AWSCredentials
    
    account_count = AWSCredentials.query.count()
    return f"Health check OK - {account_count} AWS accounts configured"

if __name__ == '__main__':
    celery.start()