from flask import Flask, render_template, request
import json

app = Flask(__name__)

# @app.route('/')
# def index():
#     return render_template('index.html')

@app.route('/')
def vulnerabilities():

    # Download the JSON file
    with open('nvdcve-1.1-2023.json', 'r', encoding='utf-8') as file:
        json_data = json.load(file)

    # Read the list of installed apps
    with open('apps_name_list.txt', 'r') as file:
        apps_list = [line.strip() for line in file]

    apps_vulnerabilities = {}
    for entry in json_data['CVE_Items']:
        description = entry['cve']['description']['description_data'][0]['value']
        cve_id = entry["cve"]["CVE_data_meta"]["ID"]

        try:
            base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
            base_severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except KeyError:
            base_score = "N/A"
            base_severity = "N/A"

        for app in apps_list:
            if f" {app.lower()} " in description.lower():
                vulnerability = {
                    'description': description,
                    'cve_id': cve_id,
                    'base_score': base_score,
                    'base_severity': base_severity
                }
                if app in apps_vulnerabilities:
                    apps_vulnerabilities[app].append(vulnerability)
                else:
                    apps_vulnerabilities[app] = [vulnerability]

    return render_template('app_list_vulnerabilities.html', vulnerabilities=apps_vulnerabilities)

if __name__ == '__main__':
    app.run()
