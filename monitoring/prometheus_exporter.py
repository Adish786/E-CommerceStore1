#!/usr/bin/env python3

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import os

class PrometheusMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4')
            self.end_headers()
            
            metrics = self.generate_metrics()
            self.wfile.write(metrics.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def generate_metrics(self):
        """Generate Prometheus metrics from vulnerability scan results."""
        metrics_lines = []
        
        # Count vulnerabilities from scan reports
        backend_metrics = self.count_vulnerabilities("reports/backend-scan.json", "backend")
        frontend_metrics = self.count_vulnerabilities("reports/frontend-scan.json", "frontend")
        
        # Add HELP and TYPE lines
        metrics_lines.extend([
            '# HELP vulnerabilities_total Total number of vulnerabilities detected',
            '# TYPE vulnerabilities_total counter',
            ''
        ])
        
        # Add backend metrics
        for severity, count in backend_metrics.items():
            if count > 0:
                metrics_lines.append(
                    f'vulnerabilities_total{{image="backend",severity="{severity.lower()}"}} {count}'
                )
        
        # Add frontend metrics
        for severity, count in frontend_metrics.items():
            if count > 0:
                metrics_lines.append(
                    f'vulnerabilities_total{{image="frontend",severity="{severity.lower()}"}} {count}'
                )
        
        # Add scan timestamp
        metrics_lines.extend([
            '',
            '# HELP vulnerability_scan_timestamp Unix timestamp of last scan',
            '# TYPE vulnerability_scan_timestamp gauge',
            f'vulnerability_scan_timestamp {int(time.time())}'
        ])
        
        return '\n'.join(metrics_lines)

    def count_vulnerabilities(self, filepath, image_name):
        """Count vulnerabilities from a JSON scan report."""
        counts = {
            "critical": 0, 
            "high": 0, 
            "medium": 0, 
            "low": 0, 
            "unknown": 0,
            "total": 0
        }
        
        try:
            with open(filepath) as f:
                data = json.load(f)
            
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    severity = vuln.get("Severity", "UNKNOWN").lower()
                    if severity in counts:
                        counts[severity] += 1
                    else:
                        counts["unknown"] += 1
                    counts["total"] += 1
                    
        except (FileNotFoundError, json.JSONDecodeError):
            # If file doesn't exist or is invalid, return zeros
            pass
            
        return counts

    def log_message(self, format, *args):
        # Suppress default HTTP logging
        pass


def start_metrics_server(port=8000):
    """Start the Prometheus metrics HTTP server."""
    server = HTTPServer(('0.0.0.0', port), PrometheusMetricsHandler)
    print(f"📊 Prometheus metrics server running on port {port}")
    print(f"📈 Metrics available at http://localhost:{port}/metrics")
    server.serve_forever()


if __name__ == "__main__":
    # Start the metrics server
    start_metrics_server()