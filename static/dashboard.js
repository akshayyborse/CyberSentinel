let threatChart;
let distributionChart;

// Initialize charts and real-time monitoring
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    startRealTimeMonitoring();
    updateStatistics();
    setInterval(updateStatistics, 30000); // Update every 30 seconds
});

function initializeCharts() {
    // Threat Analysis Chart
    const threatCtx = document.getElementById('threatGraph').getContext('2d');
    threatChart = new Chart(threatCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threat Level',
                data: [],
                borderColor: 'rgb(255, 99, 132)',
                tension: 0.1
            }, {
                label: 'Network Traffic',
                data: [],
                borderColor: 'rgb(54, 162, 235)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 1
                }
            }
        }
    });

    // Threat Distribution Chart
    const distributionCtx = document.getElementById('threatPieChart').getContext('2d');
    distributionChart = new Chart(distributionCtx, {
        type: 'doughnut',
        data: {
            labels: ['Malware', 'Network Attacks', 'Data Breaches', 'Policy Violations', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    '#ff4444',
                    '#ffbb33',
                    '#00C851',
                    '#33b5e5',
                    '#aa66cc'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

function updateTimeRange(range) {
    fetch(`/api/threat-history/${range}`)
        .then(response => response.json())
        .then(data => {
            updateThreatChart(data);
        });
}

function startRealTimeMonitoring() {
    setInterval(() => {
        fetch('/api/live-monitoring')
            .then(response => response.json())
            .then(data => {
                updateMonitoring(data);
                updateNetworkActivity(data.network_activity);
                updateLastUpdate();
            });
    }, 5000);
}

function updateMonitoring(data) {
    const alertsList = document.getElementById('alertsList');
    data.recent_alerts.forEach(alert => {
        const alertElement = document.createElement('div');
        alertElement.className = `alert-item ${alert.severity}-alert`;
        alertElement.innerHTML = `
            <div class="d-flex justify-content-between">
                <strong>${alert.timestamp}</strong>
                <span class="badge bg-${alert.severity}">${alert.severity.toUpperCase()}</span>
            </div>
            <p class="mb-0">${alert.message}</p>
            ${alert.details ? `<small class="text-muted">${alert.details}</small>` : ''}
        `;
        alertsList.prepend(alertElement);
        
        // Keep only last 50 alerts
        if (alertsList.children.length > 50) {
            alertsList.removeChild(alertsList.lastChild);
        }
    });
}

function updateNetworkActivity(activity) {
    const networkActivity = document.getElementById('networkActivity');
    activity.forEach(entry => {
        const activityElement = document.createElement('div');
        activityElement.className = `network-entry ${entry.type}`;
        activityElement.innerHTML = `
            <span class="timestamp">${entry.timestamp}</span>
            <span class="protocol">${entry.protocol}</span>
            <span class="source">${entry.source}</span>
            <span class="destination">${entry.destination}</span>
            <span class="status ${entry.status}">${entry.status}</span>
        `;
        networkActivity.prepend(activityElement);
        
        // Keep only last 100 entries
        if (networkActivity.children.length > 100) {
            networkActivity.removeChild(networkActivity.lastChild);
        }
    });
}

function updateStatistics() {
    fetch('/api/threat-stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalScans').textContent = data.total_scans;
            document.getElementById('threatsDetected').textContent = data.threats_detected;
            document.getElementById('criticalThreats').textContent = data.critical_threats;
            document.getElementById('networkHealth').textContent = `${data.network_health}%`;
            document.getElementById('networkStatus').textContent = data.network_status;
            document.getElementById('activeConnections').textContent = data.active_connections;
            document.getElementById('suspiciousConns').textContent = data.suspicious_connections;
            
            // Update threat distribution chart
            updateThreatDistribution(data.threat_distribution);
        });
}

function updateThreatDistribution(distribution) {
    distributionChart.data.datasets[0].data = [
        distribution.malware,
        distribution.network_attacks,
        distribution.data_breaches,
        distribution.policy_violations,
        distribution.other
    ];
    distributionChart.update();
}

function updateLastUpdate() {
    const now = new Date();
    document.getElementById('lastUpdate').textContent = 
        now.toLocaleTimeString();
}

function startScan() {
    const scanBtn = document.querySelector('.btn-scan');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            traffic_data: null
        })
    })
    .then(response => response.json())
    .then(data => {
        displayScanResults(data);
        updateDashboardStats(data);
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fas fa-radar"></i> Start Scan';
    })
    .catch(error => {
        console.error('Scan failed:', error);
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fas fa-radar"></i> Start Scan';
    });
}

function updateDashboardStats(data) {
    // Update network health
    const healthScore = calculateHealthScore(data);
    document.getElementById('networkHealth').textContent = `${healthScore}%`;
    document.getElementById('networkStatus').textContent = getHealthStatus(healthScore);
    
    // Update threat count
    const threatCount = data.results.active_connections.filter(conn => conn.status === 'SUSPICIOUS').length;
    document.getElementById('threatsDetected').textContent = threatCount;
    
    // Update active connections
    document.getElementById('activeConnections').textContent = data.results.active_connections.length;
    
    // Update charts
    updateCharts(data);
}

function displayScanResults(data) {
    const modal = document.getElementById('scanResultsModal');
    const statusIndicator = modal.querySelector('.status-indicator');
    const statusText = modal.querySelector('.status-text');
    
    // Show modal
    modal.classList.add('active');
    
    // Update status based on results
    if (data.results.status === 'threat_detected') {
        statusIndicator.className = 'status-indicator error';
        statusText.textContent = '⚠️ Threats Detected';
        statusText.style.color = 'var(--danger-color)';
    } else {
        statusIndicator.className = 'status-indicator success';
        statusText.textContent = '✅ Network Secure';
        statusText.style.color = 'var(--success-color)';
    }
    
    // Display network information
    const networkInfo = document.getElementById('networkInfo');
    networkInfo.innerHTML = `
        <table>
            <tr>
                <th>Hostname</th>
                <td>${data.results.network_details.hostname}</td>
            </tr>
            <tr>
                <th>Machine MAC</th>
                <td>${data.results.network_details.machine_mac}</td>
            </tr>
        </table>
        <h5 class="mt-3">Network Interfaces</h5>
        <table>
            <thead>
                <tr>
                    <th>Interface</th>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                ${Object.entries(data.results.network_details.interfaces).map(([name, info]) => `
                    <tr>
                        <td>${name}</td>
                        <td>${info.ip_address}</td>
                        <td>${info.mac_address}</td>
                        <td>
                            <span class="status-badge ${info.is_up ? 'secure' : 'warning'}">
                                ${info.is_up ? 'Active' : 'Inactive'}
                            </span>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    // Display active connections
    const connectionsInfo = document.getElementById('connectionsInfo');
    connectionsInfo.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>Status</th>
                    <th>Program</th>
                </tr>
            </thead>
            <tbody>
                ${data.results.active_connections.map(conn => `
                    <tr>
                        <td>${conn.local_address}</td>
                        <td>${conn.remote_address}</td>
                        <td>
                            <span class="status-badge ${conn.status === 'ESTABLISHED' ? 'secure' : 'warning'}">
                                ${conn.status}
                            </span>
                        </td>
                        <td>${conn.program}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    // Display packet analysis
    const packetInfo = document.getElementById('packetInfo');
    packetInfo.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Protocol</th>
                    <th>Source</th>
                    <th>Destination</th>
                </tr>
            </thead>
            <tbody>
                ${data.results.packet_analysis.map(packet => `
                    <tr>
                        <td>${packet.timestamp}</td>
                        <td>${packet.protocol}</td>
                        <td>${packet.src_ip}:${packet.src_port}</td>
                        <td>${packet.dst_ip}:${packet.dst_port}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    // Display threat information
    const threatInfo = document.getElementById('threatInfo');
    threatInfo.innerHTML = `
        <div class="threat-summary">
            <h3 class="mb-3">Scan Summary</h3>
            <p>Threat Score: ${(data.results.threat_score * 100).toFixed(2)}%</p>
            <p>Status: <span class="status-badge ${data.results.status === 'normal' ? 'secure' : 'danger'}">
                ${data.results.status === 'normal' ? 'Secure' : 'Threats Detected'}
            </span></p>
            ${data.results.countermeasures ? `
                <h4 class="mt-4">Countermeasures Initiated:</h4>
                <ul>
                    ${data.results.countermeasures.map(action => `<li>${action}</li>`).join('')}
                </ul>
            ` : ''}
        </div>
    `;
    
    // Display OWASP risk analysis
    const owaspInfo = document.getElementById('owaspInfo');
    const owaspRisks = [
        {
            name: "Broken Access Control",
            id: "A01:2021",
            description: "Failures in access restrictions, privilege escalation",
            percentage: calculateRiskPercentage(data, 'access_control')
        },
        {
            name: "Cryptographic Failures",
            id: "A02:2021",
            description: "Failures in data encryption and security",
            percentage: calculateRiskPercentage(data, 'crypto')
        },
        {
            name: "Injection",
            id: "A03:2021",
            description: "SQL, NoSQL, OS, and LDAP injection flaws",
            percentage: calculateRiskPercentage(data, 'injection')
        },
        {
            name: "Insecure Design",
            id: "A04:2021",
            description: "Design and architectural security flaws",
            percentage: calculateRiskPercentage(data, 'design')
        },
        {
            name: "Security Misconfiguration",
            id: "A05:2021",
            description: "Missing or unsafe security settings",
            percentage: calculateRiskPercentage(data, 'config')
        },
        {
            name: "Vulnerable Components",
            id: "A06:2021",
            description: "Using components with known vulnerabilities",
            percentage: calculateRiskPercentage(data, 'components')
        },
        {
            name: "Auth & Validation Failures",
            id: "A07:2021",
            description: "Authentication and data validation issues",
            percentage: calculateRiskPercentage(data, 'auth')
        },
        {
            name: "Software & Data Integrity",
            id: "A08:2021",
            description: "Code and data integrity verification issues",
            percentage: calculateRiskPercentage(data, 'integrity')
        },
        {
            name: "Logging Failures",
            id: "A09:2021",
            description: "Insufficient logging and monitoring",
            percentage: calculateRiskPercentage(data, 'logging')
        },
        {
            name: "Server-Side Request Forgery",
            id: "A10:2021",
            description: "SSRF vulnerabilities and protections",
            percentage: calculateRiskPercentage(data, 'ssrf')
        }
    ];

    owaspInfo.innerHTML = `
        <div class="owasp-grid">
            ${owaspRisks.map(risk => `
                <div class="owasp-risk-card">
                    <div class="risk-header">
                        <span class="risk-name">${risk.name}</span>
                        <span class="risk-percentage">${risk.percentage}%</span>
                    </div>
                    <div class="risk-progress">
                        <div class="risk-progress-bar ${getRiskLevel(risk.percentage)}" 
                             style="width: ${risk.percentage}%"></div>
                    </div>
                    <div class="risk-details">
                        <small>${risk.id}</small>
                        <p class="mb-0">${risk.description}</p>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function calculateRiskPercentage(data, riskType) {
    // This should be replaced with actual risk calculation logic
    // based on your threat detection algorithms
    const baseRisk = data.results.threat_score * 100;
    const randomVariation = Math.random() * 20 - 10; // +/- 10%
    return Math.min(Math.max(baseRisk + randomVariation, 0), 100).toFixed(1);
}

function getRiskLevel(percentage) {
    if (percentage >= 75) return 'critical';
    if (percentage >= 50) return 'high';
    if (percentage >= 25) return 'medium';
    return 'low';
}

function closeModal() {
    document.getElementById('scanResultsModal').classList.remove('active');
} 