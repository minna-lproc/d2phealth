# PythonAnywhere WSGI example. Replace YOUR_USERNAME and the folder name if needed.
import sys
project_path='/home/YOUR_USERNAME/community-health'
if project_path not in sys.path: sys.path.insert(0,project_path)
from app import app as application
