from app import create_app, db
from app.models import User, AWSCredentials, EC2Instance
from flask_migrate import Migrate

# Create the Flask application instance using the factory function
app = create_app()
migrate = Migrate(app, db)

@app.shell_context_processor
def make_shell_context():
    """
    Creates a shell context that adds the database instance and models
    to the shell session, making it easy to work with them in the Flask shell.
    """
    return {'db': db, 'User': User, 'AWSCredentials': AWSCredentials, 'EC2Instance': EC2Instance}

if __name__ == '__main__':
    # Running the app directly is intended for development purposes.
    # For production, a proper WSGI server like Gunicorn or uWSGI should be used.
    app.run(debug=True)