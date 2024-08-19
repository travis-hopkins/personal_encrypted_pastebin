import sys
import os

# Add the directory containing main.py to the Python path
sys.path.insert(0, '/opt/pastebin-app/app')

from main import app

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
