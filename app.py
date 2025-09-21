from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import json
import os
import bcrypt
from flask_wtf.csrf import CSRFProtect, generate_csrf
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Random key
csrf = CSRFProtect(app)

DATA_FILE = 'data.json'


def load_data():
    if os.path.exists(DATA_FILE):
        data = json.load(open(DATA_FILE, 'r', encoding='utf-8'))
        # Add background_color to groups if missing
        for group in data.get('groups', []):
            if 'background_color' not in group:
                group['background_color'] = '#ffffff'  # White by default
        # Add new fields to settings if missing
        settings = data.get('settings', {})
        if 'password_hash' not in settings:
            settings['password_hash'] = ''
        if 'auth_only' not in settings:
            settings['auth_only'] = False
        if 'allowed_ips' not in settings:
            settings['allowed_ips'] = []
        if 'csrf_secret' not in settings or not settings['csrf_secret']:
            settings['csrf_secret'] = secrets.token_hex(32)
        data['settings'] = settings
        return data
    return {"settings": {"title": "Navigation", "logo": "", "primary_color": "#4CAF50", "hover_color": "#3e8e41", "background_color": "#f2f2f2", "default_group_background_color": "#ffffff", "password_hash": "", "auth_only": False, "allowed_ips": [], "csrf_secret": secrets.token_hex(32)}, "groups": []}


def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


@app.before_request
def check_ip_and_session():
    data = load_data()
    allowed_ips = data['settings'].get('allowed_ips', [])
    if allowed_ips:
        client_ip = request.remote_addr
        if client_ip not in allowed_ips:
            return "Access denied", 403

    # Check session timeout (e.g., 30 minutes)
    if session.get('logged_in'):
        login_time_str = session.get('login_time')
        if login_time_str:
            login_time = datetime.fromisoformat(login_time_str)
            if datetime.now() - login_time > timedelta(minutes=30):
                session.pop('logged_in', None)
                session.pop('login_time', None)
                flash('Session expired, please log in again')
                return redirect(url_for('login'))


@app.route('/')
def index():
    data = load_data()
    if data['settings'].get('auth_only', False) and not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html', data=data)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    if request.method == 'POST':
        # Update settings
        data['settings']['title'] = request.form.get('title', data['settings']['title'])
        data['settings']['logo'] = request.form.get('logo', data['settings']['logo'])
        data['settings']['primary_color'] = request.form.get('primary_color', data['settings']['primary_color'])
        data['settings']['hover_color'] = request.form.get('hover_color', data['settings']['hover_color'])
        data['settings']['background_color'] = request.form.get('background_color', data['settings']['background_color'])
        data['settings']['navbar_color'] = request.form.get('navbar_color', data['settings']['navbar_color'])
        data['settings']['text_color'] = request.form.get('text_color', data['settings']['text_color'])
        data['settings']['font_family'] = request.form.get('font_family', data['settings']['font_family'])
        data['settings']['default_group_background_color'] = request.form.get('default_group_background_color', data['settings']['default_group_background_color'])
        # Security settings
        data['settings']['auth_only'] = 'auth_only' in request.form
        allowed_ips_str = request.form.get('allowed_ips', '')
        data['settings']['allowed_ips'] = [ip.strip() for ip in allowed_ips_str.split(',') if ip.strip()]
        save_data(data)
        flash('Settings updated')
        return redirect(url_for('admin'))
    return render_template('admin.html', data=data)


@app.route('/login', methods=['GET', 'POST'])
def login():
    data = load_data()
    if request.method == 'POST':
        password = request.form.get('password')
        password_hash = data['settings'].get('password_hash', '')
        if not password_hash:
            # If password is not set, set 'admin'
            hashed = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
            data['settings']['password_hash'] = hashed.decode('utf-8')
            save_data(data)
            password_hash = hashed.decode('utf-8')
        if password_hash and bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            session['logged_in'] = True
            session['login_time'] = datetime.now().isoformat()
            return redirect(url_for('admin'))
        flash('Invalid password')
    return render_template('login.html', data=data)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('login_time', None)
    return redirect(url_for('index'))


@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    password_hash = data['settings'].get('password_hash', '')
    if password_hash and current_password and not bcrypt.checkpw(current_password.encode('utf-8'), password_hash.encode('utf-8')):
        flash('Invalid current password')
        return redirect(url_for('admin'))
    if new_password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('admin'))
    if not new_password or len(new_password) < 6:
        flash('Password must be at least 6 characters')
        return redirect(url_for('admin'))
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    data['settings']['password_hash'] = hashed.decode('utf-8')
    save_data(data)
    flash('Password changed')
    return redirect(url_for('admin'))


@app.route('/add_group', methods=['POST'])
def add_group():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    name = request.form.get('name')
    background_color = request.form.get('background_color', '#ffffff')
    if name:
        data['groups'].append({"name": name, "links": [], "background_color": background_color})
        save_data(data)
    return redirect(url_for('admin'))


@app.route('/delete_group/<int:group_id>')
def delete_group(group_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    if 0 <= group_id < len(data['groups']):
        del data['groups'][group_id]
        save_data(data)
    return redirect(url_for('admin'))


@app.route('/add_link/<int:group_id>', methods=['POST'])
def add_link(group_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    if 0 <= group_id < len(data['groups']):
        url = request.form.get('url')
        title = request.form.get('title')
        description = request.form.get('description', '')
        if url and title:
            data['groups'][group_id]['links'].append({"url": url, "title": title, "description": description})
            save_data(data)
    return redirect(url_for('admin'))


@app.route('/delete_link/<int:group_id>/<int:link_id>')
def delete_link(group_id, link_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    if 0 <= group_id < len(data['groups']) and 0 <= link_id < len(data['groups'][group_id]['links']):
        del data['groups'][group_id]['links'][link_id]
        save_data(data)
    return redirect(url_for('admin'))


@app.route('/edit_group/<int:group_id>', methods=['POST'])
def edit_group(group_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    if 0 <= group_id < len(data['groups']):
        new_name = request.form.get('name')
        new_background_color = request.form.get('background_color')
        if new_name:
            data['groups'][group_id]['name'] = new_name
        if new_background_color:
            data['groups'][group_id]['background_color'] = new_background_color
        save_data(data)
    return redirect(url_for('admin'))


@app.route('/edit_link/<int:group_id>/<int:link_id>', methods=['POST'])
def edit_link(group_id, link_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = load_data()
    if 0 <= group_id < len(data['groups']) and 0 <= link_id < len(data['groups'][group_id]['links']):
        url = request.form.get('url')
        title = request.form.get('title')
        description = request.form.get('description', '')
        if url and title:
            data['groups'][group_id]['links'][link_id] = {"url": url, "title": title, "description": description}
            save_data(data)
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=True)