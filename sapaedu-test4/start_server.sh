
#!/bin/bash

# SapaEdu Server Startup Script

echo "Starting SapaEdu application..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "pip3 is not installed. Please install pip3 first."
    exit 1
fi

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Set default environment variables if not set
export BOT_TOKEN=${BOT_TOKEN:-"8317598561:AAG4kb5Dh1NxVTGLS60FIFy6_8UIHwh_RSo"}
export GROUP_ID=${GROUP_ID:-"-1002723413852"}
export DATABASE_URL=${DATABASE_URL:-"postgresql://admin:Aa123456@10.128.0.79:5432/sapaedu"}
export SECRET_KEY=${SECRET_KEY:-"your-secret-key-here-change-in-production"}
export USE_FALLBACK_DATA=${USE_FALLBACK_DATA:-"false"}

# Start the application
echo "Starting Flask application..."
python3 main.py
