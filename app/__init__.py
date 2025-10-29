"""
app/__init__.py - Application Factory
Blueprint registration with correct url_prefix
Fixed: Added root route redirect and updated Celery configuration
"""
from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from config import Config
from .extensions import celery
from datetime import datetime

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'


def create_app(config_class=Config):
    """Application factory function."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    if not app.config['ENCRYPTION_KEY']:
        raise ValueError("ENCRYPTION_KEY is missing.")

    db.init_app(app)
    Migrate(app, db)
    login_manager.init_app(app)

    # Celery configuration - use REDIS_URL directly to avoid KeyError
    celery.conf.update(app.config)
    redis_url = app.config['REDIS_URL']
    celery.conf.update(
        CELERY_BROKER_URL=redis_url,
        CELERY_RESULT_BACKEND=redis_url
    )
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask

    # Root route - redirect to dashboard
    @app.route('/')
    def root():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.index'))
        return redirect(url_for('auth.login'))
    
    @app.template_filter('timeago')
    def timeago_filter(datetime_obj):
        if not datetime_obj:
            return 'Never'
        diff = datetime.utcnow() - datetime_obj
        if diff.days > 7:
            return datetime_obj.strftime('%Y-%m-%d')
        elif diff.days > 0:
            return f'{diff.days} days ago'
        elif diff.seconds > 3600:
            return f'{diff.seconds // 3600} hours ago'
        else:
            return f'{diff.seconds // 60} minutes ago'

    # Register blueprints with correct url_prefix
    from app.auth.routes import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    from app.dashboard.routes import bp as dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

    # Import tasks module to register them with Celery
    from app import tasks

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return db.session.get(User, int(user_id))

    return app