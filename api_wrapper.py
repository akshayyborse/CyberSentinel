import requests
import json

class CyberSentinelAPI:
    def __init__(self, base_url="http://localhost:5000", api_key=None):
        self.base_url = base_url
        self.api_key = api_key
        self.device_id = None

    def register_device(self, device_info):
        """Register a new mobile device"""
        response = self._make_request('mobile/register', device_info)
        if response.get('status') == 'success':
            self.device_id = response.get('device_id')
        return response

    def sync_data(self):
        """Sync device data with server"""
        return self._make_request('mobile/sync', {
            'device_id': self.device_id,
            'last_sync': self.last_sync
        })

    def report_threat(self, threat_data):
        """Report a detected threat"""
        return self._make_request('mobile/report-threat', {
            'device_id': self.device_id,
            'threat_data': threat_data
        })

    def _make_request(self, endpoint, data):
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': self.api_key
        }
        try:
            response = requests.post(
                f"{self.base_url}/api/{endpoint}",
                json=data,
                headers=headers
            )
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": str(e)}

    def scan_network(self, traffic_data=None):
        """
        Send network traffic data to the CyberSentinel server for analysis
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/scan",
                json={"traffic_data": traffic_data}
            )
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": str(e)} 