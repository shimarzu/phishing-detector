from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyze_email
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

scan_history = []

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email_text = data.get('email', '')
    subject = data.get('subject', '')
    sender = data.get('sender', '')

    if not email_text and not subject and not sender:
        return jsonify({'error': 'Email content is required'}), 400

    result = analyze_email(sender, subject, email_text)
    result['timestamp'] = datetime.now().isoformat()
    result['id'] = len(scan_history) + 1

    scan_history.append(result)

    return jsonify(result)


@app.route('/api/history', methods=['GET'])
def history():
    return jsonify(scan_history[-20:])


@app.route('/api/stats', methods=['GET'])
def stats():
    total = len(scan_history)
    phishing = sum(1 for r in scan_history if r['verdict'] == 'phishing')
    suspicious = sum(1 for r in scan_history if r['verdict'] == 'suspicious')
    safe = sum(1 for r in scan_history if r['verdict'] == 'safe')
    return jsonify({
        'total': total,
        'phishing': phishing,
        'suspicious': suspicious,
        'safe': safe
    })


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
