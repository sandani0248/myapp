import os
from dotenv import load_dotenv
from celery.schedules import crontab

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    """Application configuration settings."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-should-really-set-a-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'

    # --- CELERY CONFIGURATION (Old Format) ---
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL
    
    # Additional Celery settings
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True


# Inside config.py
# --- CELERY BEAT SCHEDULE ---

CELERY_BEAT_SCHEDULE = {
    'check-backup-schedules-every-minute': {
        'task': 'app.tasks.check_backup_schedules',
        'schedule': 60.0,  # Run every 60 seconds (1 minute)
    },
    'cleanup-old-backup-logs-daily': {
        'task': 'app.tasks.cleanup_old_backup_logs',
        'schedule': crontab(hour=0, minute=0),  # Daily at midnight
    },
    'prune-old-snapshots-daily': {
        'task': 'app.tasks.prune_old_snapshots',
        'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
    },
}

    # CELERY_BEAT_SCHEDULE = {
    #     'check-backup-schedules-every-minute': {
    #         'task': 'app.tasks.check_backup_schedules', # <-- This is the Ticker task
    #         'schedule': 60.0, # Run every 60 seconds
    #         # No arguments are passed, so it works.
    #     },
    #     'prune-old-snapshots-daily': {
    #         'task': 'app.tasks.prune_old_snapshots',
    #         'schedule': crontab(hour=4, minute=0), # Run once per day at 4 AM
    #     },
    # }

    # --- END OF CELERY CONFIG ---



# import os
# from dotenv import load_dotenv

# basedir = os.path.abspath(os.path.dirname(__file__))
# load_dotenv(os.path.join(basedir, '.env'))

# class Config:
#     """Application configuration settings."""
#     SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-should-really-set-a-secret-key'
#     SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
#         'sqlite:///' + os.path.join(basedir, 'app.db')
#     SQLALCHEMY_TRACK_MODIFICATIONS = False
#     ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
#     AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'

#     # --- ADD THESE TWO LINES ---
#     REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
#     CELERY_BROKER_URL = REDIS_URL # Use REDIS_URL for broker
#     CELERY_RESULT_BACKEND = REDIS_URL # Use REDIS_URL for backend
#     # --- END OF ADDED LINES ---