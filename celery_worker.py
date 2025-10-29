import os
from celery import Celery
from celery.schedules import crontab
from app import create_app

# Create the Flask app context
flask_app = create_app()

def make_celery(app):
    """
    Configure and create a Celery instance.
    The broker is the message queue (Redis),
    and the backend stores task results (also Redis).
    """
    # Get Redis URL from config, with fallback
    redis_url = app.config.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    celery = Celery(
        app.import_name,
        backend=redis_url,
        broker=redis_url
    )
    
    # Explicitly set broker and backend again to override any defaults
    celery.conf.broker_url = redis_url
    celery.conf.result_backend = redis_url
    
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        """Ensure Celery tasks run inside Flask app context"""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

# Create and expose Celery instance
celery = make_celery(flask_app)

# Logging to debug broker configuration
print(f"Celery broker URL: {celery.conf.broker_url}")
print(f"Celery result backend: {celery.conf.result_backend}")

# Configure beat schedule for periodic tasks
celery.conf.beat_schedule = {
    'check-backup-schedules': {
        'task': 'app.tasks.check_backup_schedules',
        'schedule': 60.0,  # Run every minute
    },
    'prune-old-snapshots-daily': {
        'task': 'app.tasks.prune_old_snapshots',
        'schedule': crontab(hour=4, minute=0),  # Run at 4 AM daily
    },
    'sync-all-accounts-daily': {
        'task': 'app.tasks.sync_all_accounts',
        'schedule': crontab(hour=3, minute=0),  # Run at 3 AM daily
    },
    'cleanup-old-backups': {
        'task': 'app.tasks.cleanup_old_backups',
        'schedule': crontab(hour=4, minute=30),  # Run at 4:30 AM daily
    },
}

# Other Celery configuration
celery.conf.timezone = 'UTC'