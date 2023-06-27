# app.py
from flask import Flask, render_template, request
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/vulnerabilities', methods=['POST'])
def vulnerabilities():
    keyword = request.form.get('keyword')

    # Download the JSON file
    with open('data/nvdcve-1.1-2023.json', 'r', encoding='utf-8') as file:
        json_data = json.load(file)

    vulnerabilities = []
    for entry in json_data['CVE_Items']:
        description = entry['cve']['description']['description_data'][0]['value']
        cve_id = entry["cve"]["CVE_data_meta"]["ID"]

        try:
            base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
            base_severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except KeyError:
            base_score = "N/A"
            base_severity = "N/A"
        
        if f" {keyword.lower()} " in description.lower(): #added space on both sides of keyword for better matching
            vulnerability = {
                'description': description,
                'cve_id': cve_id,
                'base_score': base_score,
                'base_severity': base_severity
            }
            vulnerabilities.append(vulnerability)
    
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities, keyword=keyword)

if __name__ == '__main__':
    app.run()
