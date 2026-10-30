import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from detector import ScamDetector
import database as db

app = Flask(__name__)
app.secret_key = 'scamshield_secure_key_default'

# Initialize database
db.init_db()

detector = ScamDetector()

@app.route('/')
def index():
    stats = db.get_dashboard_stats()
    return render_template('index.html', stats=stats)

@app.route('/scan', methods=['POST'])
def scan():
    if request.is_json:
        data = request.get_json()
        message = data.get('message', '').strip()
    else:
        message = request.form.get('message', '').strip()

    if not message:
        if request.is_json:
            return jsonify({'error': 'Message content cannot be empty.'}), 400
        flash('Please enter a message or URL to scan.', 'danger')
        return redirect(url_for('index'))

    if len(message) > 5000:
        if request.is_json:
            return jsonify({'error': 'Message exceeds maximum length limit of 5,000 characters.'}), 400
        flash('Message is too long. Maximum allowed length is 5000 characters.', 'warning')
        return redirect(url_for('index'))

    # Run Detection Analysis
    result = detector.analyze_message(message)

    # Save to SQLite Database
    scan_id = db.save_scan_result(
        message=message,
        risk_score=result['score'],
        risk_level=result['level'],
        indicators_json=json.dumps(result['indicators']),
        recommendations_json=json.dumps(result['recommendations'])
    )

    result['scan_id'] = scan_id

    if request.is_json:
        return jsonify(result)

    return render_template('results.html', result=result, message=message)

@app.route('/history')
def history():
    scans = db.get_all_scans()
    return render_template('history.html', scans=scans)

@app.route('/history/<int:scan_id>')
def view_scan(scan_id):
    scan_data = db.get_scan_by_id(scan_id)
    if not scan_data:
        flash('Scan record not found.', 'danger')
        return redirect(url_for('history'))

    result = {
        'scan_id': scan_data['id'],
        'score': scan_data['risk_score'],
        'level': scan_data['risk_level'],
        'indicators': json.loads(scan_data['indicators_json']),
        'recommendations': json.loads(scan_data['recommendations_json']),
        'timestamp': scan_data['timestamp']
    }

    return render_template('results.html', result=result, message=scan_data['message'])

@app.route('/clear_history', methods=['POST'])
def clear_history():
    db.clear_scan_history()
    flash('Scan history cleared successfully.', 'success')
    return redirect(url_for('history'))

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
