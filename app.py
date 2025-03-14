from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from cybersentinel import CyberSentinel
import numpy as np
import json
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')
login_manager = LoginManager()
login_manager.init_app(app)
sentinel = CyberSentinel()

# Simple user model (replace with database in production)
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

users = {}  # In-memory user store (use a database in production)

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Add proper user authentication here
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/scan-history')
@login_required
def get_scan_history():
    # Return last 10 scans
    return jsonify(sentinel.get_scan_history(limit=10))

@app.route('/api/threat-stats')
@login_required
def get_threat_stats():
    return jsonify({
        'total_scans': sentinel.total_scans,
        'threats_detected': sentinel.threats_detected,
        'critical_threats': sentinel.critical_threats,
        'network_health': sentinel.calculate_network_health(),
        'network_status': sentinel.get_network_status(),
        'active_connections': sentinel.get_active_connections(),
        'suspicious_connections': sentinel.get_suspicious_connections(),
        'threat_distribution': {
            'malware': sentinel.get_threat_count('malware'),
            'network_attacks': sentinel.get_threat_count('network'),
            'data_breaches': sentinel.get_threat_count('breach'),
            'policy_violations': sentinel.get_threat_count('policy'),
            'other': sentinel.get_threat_count('other')
        }
    })

@app.route('/api/threat-history/<timerange>')
@login_required
def get_threat_history(timerange):
    return jsonify(sentinel.get_threat_history(timerange))

@app.route('/api/live-monitoring')
@login_required
def get_live_monitoring():
    return jsonify({
        'recent_alerts': sentinel.get_recent_alerts(),
        'network_activity': sentinel.get_network_activity()
    })

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_network():
    try:
        traffic_data = request.json.get('traffic_data')
        if not traffic_data:
            traffic_data = np.random.rand(1, 100).tolist()
        
        traffic_array = np.array(traffic_data)
        scan_results = sentinel.scan_network_traffic(traffic_array)
        
        return jsonify({
            'status': 'success',
            'results': scan_results,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/mobile/register', methods=['POST'])
def mobile_register():
    data = request.json
    # Implement device registration
    return jsonify({'status': 'success', 'device_id': 'generated_id'})

@app.route('/api/mobile/sync', methods=['POST'])
def mobile_sync():
    data = request.json
    # Implement data synchronization
    return jsonify({'status': 'success', 'updates': []})

@app.route('/api/mobile/report-threat', methods=['POST'])
def mobile_report_threat():
    data = request.json
    # Process and store threat report
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 