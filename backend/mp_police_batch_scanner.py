"""
MP Police Batch APK Scanner
Simple command-line tool for batch scanning APK directories
"""

import os
import sys
import json
import requests
from pathlib import Path
from datetime import datetime

class MPPoliceBatchScanner:
    def __init__(self, api_url="http://127.0.0.1:5000"):
        self.api_url = api_url
        self.results = []
        
    def scan_directory(self, directory_path, output_file=None):
        directory = Path(directory_path)
        if not directory.exists():
            print(f"[ERROR] Directory not found: {directory_path}")
            return False
        
        apk_files = list(directory.glob("**/*.apk"))
        
        if len(apk_files) == 0:
            return True
        
        for apk_file in apk_files:
            try:
                with open(apk_file, 'rb') as f:
                    files = {'file': (apk_file.name, f, 'application/vnd.android.package-archive')}
                    response = requests.post(f"{self.api_url}/api/analyze", files=files, timeout=30)
                    
                    if response.status_code == 200:
                        result = response.json()
                        analysis = result.get('analysis', {})
                        
                        scan_result = {
                            'filename': apk_file.name,
                            'path': str(apk_file),
                            'size_mb': apk_file.stat().st_size / (1024 * 1024),
                            'classification': analysis.get('classification', 'UNKNOWN'),
                            'confidence': analysis.get('confidence', 0.0),
                            'timestamp': datetime.now().isoformat()
                        }
                        self.results.append(scan_result)
                        
                    else:
                        self.results.append({
                            'filename': apk_file.name,
                            'path': str(apk_file),
                            'classification': 'ERROR',
                            'error': f"API Error: {response.status_code}",
                            'timestamp': datetime.now().isoformat()
                        })
                        
            except Exception as e:
                self.results.append({
                    'filename': apk_file.name,
                    'path': str(apk_file),
                    'classification': 'ERROR',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        if output_file:
            self.save_results(output_file)
        return True
    
    def save_results(self, output_file):
        try:
            report = {
                'scan_timestamp': datetime.now().isoformat(),
                'total_scanned': len(self.results),
                'summary': {
                    'legitimate': len([r for r in self.results if r.get('classification') == 'LEGITIMATE']),
                    'suspicious': len([r for r in self.results if r.get('classification') == 'SUSPICIOUS']),
                    'errors': len([r for r in self.results if r.get('classification') == 'ERROR'])
                },
                'results': self.results
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[ERROR] Failed to save results: {str(e)}")
    
    def scan_banking_apks(self):
        banking_dir = Path(__file__).parent / "mp_police_datasets" / "legitimate" / "banking"
        output_file = Path(__file__).parent / "mp_police_scan_results.json"
        return self.scan_directory(str(banking_dir), str(output_file))

def main():
    if len(sys.argv) < 2:
        print("MP Police Batch APK Scanner")
        print("Usage:")
        print("  python mp_police_batch_scanner.py <directory_path> [output_file.json]")
        print("  python mp_police_batch_scanner.py --banking  # Scan banking APKs dataset")
        return
    
    scanner = MPPoliceBatchScanner()
    
    if sys.argv[1] == "--banking":
        scanner.scan_banking_apks()
    else:
        directory_path = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        scanner.scan_directory(directory_path, output_file)

if __name__ == "__main__":
    main()
