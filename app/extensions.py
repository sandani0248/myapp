from celery import Celery

# Create the celery instance that will be configured and used by the rest of the app
celery = Celery(__name__)