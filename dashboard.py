import json
from flask import Flask, render_template_string

app = Flask(__name__)


def load_alerts():
    try:
        alerts_file = open("alerts.json", "r")
        alerts = json.load(alerts_file)
        alerts_file.close()
        return alerts
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []


@app.route("/")
def dashboard():
    alerts = load_alerts()

    page = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Mini SOC Dashboard</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 30px;
                background-color: #f4f6f8;
                color: #222;
            }

            h1 {
                margin-bottom: 10px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background-color: white;
            }

            th, td {
                padding: 12px;
                border: 1px solid #ddd;
                text-align: left;
            }

            th {
                background-color: #202936;
                color: white;
            }

            .LOW {
                color: #9a6b00;
                font-weight: bold;
            }

            .MEDIUM {
                color: #9b268f;
                font-weight: bold;
            }

            .HIGH {
                color: #c62828;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Mini SOC Dashboard</h1>
        <p>Total alerts: {{ alerts|length }}</p>

        {% if alerts %}
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Severity</th>
                    <th>Failed Attempts</th>
                    <th>Attack Duration</th>
                    <th>Generated At</th>
                </tr>

                {% for alert in alerts %}
                    <tr>
                        <td>{{ alert.ip_address }}</td>
                        <td class="{{ alert.severity }}">{{ alert.severity }}</td>
                        <td>{{ alert.failed_attempt_count }}</td>
                        <td>{{ alert.attack_duration }}</td>
                        <td>{{ alert.generated_at }}</td>
                    </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>No alerts found. Run main.py first to generate alerts.json.</p>
        {% endif %}
    </body>
    </html>
    """

    return render_template_string(page, alerts=alerts)


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
