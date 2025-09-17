# Gunicorn configuration for GBot Web App - Ubuntu Compatible
import multiprocessing
import os

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = 2  # Reduced for stability
worker_class = "sync"
worker_connections = 1000
timeout = 600  # 10 minutes timeout for long-running operations
keepalive = 2

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'gbot-web-app'

# Server mechanics
daemon = False
pidfile = '/tmp/gbot.pid'
user = None
group = None
tmp_upload_dir = None

# SSL (if needed)
keyfile = None
certfile = None

# Preload app for better performance
preload_app = False  # Changed to False for better compatibility
