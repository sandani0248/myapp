from flask import render_template, flash, redirect, url_for, request, Blueprint
from flask_login import login_user, logout_user, current_user, login_required
from urllib.parse import urlparse
# from urllib.parse import urlparse
from app import db
from app.models import User
# A simple form can be handled directly in the route for this example.
# For more complex scenarios, use Flask-WTF.

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me') is not None
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))
        login_user(user, remember=remember_me)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('dashboard.index')
        return redirect(next_page)
    return render_template('auth/login.html', title='Sign In')

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('dashboard.index'))

# In a real app, you'd have a registration route. For this example,
# we can add a user via the Flask shell.
# from app.models import User
# from app import db
# u = User(username='admin', email='admin@example.com')
# u.set_password('your-strong-password')
# db.session.add(u)
# db.session.commit()