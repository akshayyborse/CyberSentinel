document.getElementById('scanBtn').addEventListener('click', function() {
    const scanningStatus = document.getElementById('scanningStatus');
    const results = document.getElementById('results');
    
    // Show scanning status
    scanningStatus.classList.remove('d-none');
    scanningStatus.classList.add('scanning-animation');
    results.innerHTML = '';
    
    // Call the API
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            traffic_data: null  // Server will generate sample data
        })
    })
    .then(response => response.json())
    .then(data => {
        scanningStatus.classList.add('d-none');
        
        displayScanResults(data);
    })
    .catch(error => {
        scanningStatus.classList.add('d-none');
        results.innerHTML = `
            <div class="alert alert-danger">
                Error: ${error.message}
            </div>
        `;
    });
});

function displayScanResults(data) {
    const results = document.getElementById('results');
    
    // Create detailed results HTML
    let resultsHTML = `
        <div class="scan-results">
            <h3>Scan Results - ${data.timestamp}</h3>
            
            <div class="card mb-3">
                <div class="card-header">
                    <h4>Network Details</h4>
                </div>
                <div class="card-body">
                    <p><strong>Hostname:</strong> ${data.results.network_details.hostname}</p>
                    <p><strong>Machine MAC:</strong> ${data.results.network_details.machine_mac}</p>
                    
                    <h5>Network Interfaces:</h5>
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Interface</th>
                                    <th>IP Address</th>
                                    <th>MAC Address</th>
                                    <th>Netmask</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${Object.entries(data.results.network_details.interfaces).map(([name, info]) => `
                                    <tr>
                                        <td>${name}</td>
                                        <td>${info.ip_address}</td>
                                        <td>${info.mac_address}</td>
                                        <td>${info.netmask}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="card mb-3">
                <div class="card-header">
                    <h4>Active Connections</h4>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
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
                                        <td>${conn.status}</td>
                                        <td>${conn.program}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="card mb-3">
                <div class="card-header">
                    <h4>Recent Packet Analysis</h4>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
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
                    </div>
                </div>
            </div>

            ${data.results.status === 'threat_detected' ? `
                <div class="alert alert-danger">
                    <h4>⚠️ Threats Detected!</h4>
                    <ul>
                        ${data.results.countermeasures.map(action => `<li>${action}</li>`).join('')}
                    </ul>
                </div>
            ` : `
                <div class="alert alert-success">
                    <h4>✅ Network Status: Normal</h4>
                    <p>Threat Score: ${(data.results.threat_score * 100).toFixed(2)}%</p>
                </div>
            `}
        </div>
    `;
    
    results.innerHTML = resultsHTML;
} 