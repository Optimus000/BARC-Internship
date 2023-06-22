from flask import Flask, render_template, request
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/vulnerabilities', methods=['POST'])
def vulnerabilities():
    application_name = request.form.get('application_name')

    # Download the JSON file
    with open('nvdcve-1.1-2023.json', 'r', encoding='utf-8') as file:
        json_data = json.load(file)

    vulnerabilities = []
    for entry in json_data['CVE_Items']:
        description = entry['cve']['description']['description_data'][0]['value']
        
        try:
            base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
            base_severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except KeyError:
            base_score = "N/A"
            base_severity = "N/A"
        
        if application_name.lower() in description.lower():
            vulnerability = {
                'description': description,
                'base_score': base_score,
                'base_severity': base_severity
            }
            vulnerabilities.append(vulnerability)
    
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    app.run()
