import json
from flask import Flask, render_template_string
from collections import defaultdict

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

    total_alerts = len(alerts)
    low_count = sum(1 for alert in alerts if alert.get('severity') == 'LOW')
    medium_count = sum(1 for alert in alerts if alert.get('severity') == 'MEDIUM')
    high_count = sum(1 for alert in alerts if alert.get('severity') == 'HIGH')

    # Data for charts
    severity_labels = ['LOW', 'MEDIUM', 'HIGH']
    severity_data = [low_count, medium_count, high_count]

    ip_attempts = defaultdict(int)
    for alert in alerts:
        ip_attempts[alert['ip_address']] += alert['failed_attempt_count']
    ip_labels = list(ip_attempts.keys())
    attempts_data = list(ip_attempts.values())

    page = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Mini SOC Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #000000 0%, #8B0000 100%);
                color: #fff;
                min-height: 100vh;
            }

            h1 {
                text-align: center;
                color: white;
                margin-bottom: 30px;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.8);
            }

            h2 {
                text-align: center;
                color: #fff;
                margin-bottom: 15px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background-color: #1a1a1a;
                border-radius: 0;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0,0,0,0.5);
            }

            th, td {
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid #333;
            }

            th {
                background: #8B0000;
                color: white;
                font-weight: 600;
            }

            tr:nth-child(even) {
                background-color: #2a2a2a;
            }

            tr:hover {
                background-color: #3a3a3a;
                transition: background-color 0.3s ease;
            }

            .LOW {
                color: #ffd700;
                font-weight: bold;
            }

            .MEDIUM {
                color: #ff8c00;
                font-weight: bold;
            }

            .HIGH {
                color: #ff4500;
                font-weight: bold;
            }

            .card-container {
                display: flex;
                justify-content: space-around;
                margin-bottom: 30px;
                flex-wrap: wrap;
            }

            .card {
                background: linear-gradient(135deg, #2c2c2c 0%, #4c0000 100%);
                border-radius: 0;
                padding: 25px;
                text-align: center;
                width: 20%;
                min-width: 150px;
                box-shadow: 0 8px 15px rgba(0,0,0,0.8);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                color: white;
                margin: 10px;
                border: 2px solid #8B0000;
            }

            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 12px 20px rgba(0,0,0,0.9);
            }

            .card h3 {
                margin: 0;
                font-size: 2.5em;
                color: #ff4444;
            }

            .card p {
                margin: 10px 0 0 0;
                font-weight: 500;
                color: #ccc;
            }

            .chart-container {
                display: flex;
                justify-content: space-around;
                margin-bottom: 30px;
                flex-wrap: wrap;
            }

            .chart {
                width: 45%;
                min-width: 300px;
                background-color: #1a1a1a;
                border-radius: 0;
                padding: 25px;
                box-shadow: 0 8px 15px rgba(0,0,0,0.8);
                margin: 10px;
                border: 2px solid #8B0000;
            }

            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                height: 100vh;
                width: 200px;
                background: #000;
                padding: 20px;
                box-shadow: 2px 0 5px rgba(0,0,0,0.5);
                z-index: 1000;
                box-sizing: border-box;
            }

            .tab-button {
                display: block;
                width: 100%;
                padding: 15px;
                margin-bottom: 10px;
                background: #8B0000;
                color: white;
                border: none;
                cursor: pointer;
                text-align: left;
                font-size: 16px;
                transition: background 0.3s;
            }

            .tab-button:hover {
                background: #B22222;
            }

            .tab-button.active {
                background: #FF0000;
            }

            .refresh-btn {
                display: block;
                width: 100%;
                padding: 15px;
                margin-bottom: 10px;
                background: #2a2a2a;
                color: #ffd700;
                border: 2px solid #8B0000;
                cursor: pointer;
                text-align: center;
                font-size: 16px;
                font-weight: bold;
                transition: background 0.3s;
                margin-top: 20px;
            }

            .refresh-btn:hover {
                background: #3a3a3a;
            }

            .main-content {
                margin-left: 240px;
                padding: 20px;
            }

            .tab-content {
                display: none;
            }

            .tab-content.active {
                display: block;
            }
        </style>
    </head>
    <body>
        <div class="sidebar">
            <button class="tab-button active" onclick="showTab('dashboard')">Dashboard</button>
            <button class="tab-button" onclick="showTab('charts')">Charts</button>
            <button class="tab-button" onclick="showTab('ips')">IP Addresses</button>
            <button class="refresh-btn" onclick="location.reload()">🔄 Refresh Data</button>
        </div>
        <div class="main-content">
            <div id="dashboard" class="tab-content active">
                <h1>Mini SOC Dashboard</h1>

                <div class="card-container">
                    <div class="card">
                        <h3>{{ total_alerts }}</h3>
                        <p>Total Alerts</p>
                    </div>
                    <div class="card">
                        <h3>{{ low_count }}</h3>
                        <p>Low Severity</p>
                    </div>
                    <div class="card">
                        <h3>{{ medium_count }}</h3>
                        <p>Medium Severity</p>
                    </div>
                    <div class="card">
                        <h3>{{ high_count }}</h3>
                        <p>High Severity</p>
                    </div>
                </div>

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
                    <div style="text-align: center; background: #1a1a1a; padding: 30px; border-radius: 0; box-shadow: 0 8px 15px rgba(0,0,0,0.8); border: 2px solid #8B0000;">
                        <p style="font-size: 1.2em; color: #ccc;">No alerts found. Run main.py first to generate alerts.json.</p>
                    </div>
                {% endif %}
            </div>

            <div id="charts" class="tab-content">
                <h1>Charts</h1>
                <div class="chart-container">
                    <div class="chart">
                        <h2>Alert Severity Distribution</h2>
                        <canvas id="severityChart"></canvas>
                    </div>
                    <div class="chart">
                        <h2>Failed Attempts per IP</h2>
                        <canvas id="ipChart"></canvas>
                    </div>
                </div>
            </div>

            <div id="ips" class="tab-content">
                <h1>IP Addresses</h1>
                {% if ip_attempts %}
                    <table>
                        <tr>
                            <th>IP Address</th>
                            <th>Failed Attempts</th>
                        </tr>
                        {% for ip, count in ip_attempts.items() %}
                            <tr>
                                <td>{{ ip }}</td>
                                <td>{{ count }}</td>
                            </tr>
                        {% endfor %}
                    </table>
                {% else %}
                    <div style="text-align: center; background: #1a1a1a; padding: 30px; border-radius: 0; box-shadow: 0 8px 15px rgba(0,0,0,0.8); border: 2px solid #8B0000;">
                        <p style="font-size: 1.2em; color: #ccc;">No IP data available.</p>
                    </div>
                {% endif %}
            </div>
        </div>
        <script>
            let chartsCreated = false;

            function showTab(tabName) {
                // Hide all tab contents
                const contents = document.querySelectorAll('.tab-content');
                contents.forEach(content => content.classList.remove('active'));

                // Remove active class from buttons
                const buttons = document.querySelectorAll('.tab-button');
                buttons.forEach(button => button.classList.remove('active'));

                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');

                // Create charts if charts tab is selected and not created yet
                if (tabName === 'charts' && !chartsCreated) {
                    createCharts();
                    chartsCreated = true;
                }
            }

            function createCharts() {
                const ctx = document.getElementById('severityChart').getContext('2d');
                new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: {{ severity_labels|tojson }},
                        datasets: [{
                            data: {{ severity_data|tojson }},
                            backgroundColor: ['#ffd700', '#ff8c00', '#ff4500']
                        }]
                    }
                });

                const ctx2 = document.getElementById('ipChart').getContext('2d');
                new Chart(ctx2, {
                    type: 'bar',
                    data: {
                        labels: {{ ip_labels|tojson }},
                        datasets: [{
                            label: 'Failed Attempts',
                            data: {{ attempts_data|tojson }},
                            backgroundColor: '#8B0000'
                        }]
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }
        </script>
    </body>
    </html>
    """

    return render_template_string(page, alerts=alerts, total_alerts=total_alerts, low_count=low_count, medium_count=medium_count, high_count=high_count, severity_labels=severity_labels, severity_data=severity_data, ip_labels=ip_labels, attempts_data=attempts_data, ip_attempts=ip_attempts)


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
