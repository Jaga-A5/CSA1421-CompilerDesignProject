"""
Startup script for VulnX Web Application
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting VulnX Web Application on port {port}...")
    print(f"Access the application at: http://localhost:{port}")
    print("Press Ctrl+C to stop the server")
    app.run(debug=False, host='0.0.0.0', port=port)
