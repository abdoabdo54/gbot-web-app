# Gunicorn configuration for high-load production
import multiprocessing
import os

# Server socket - MAXIMUM for high load
bind = "127.0.0.1:5000"
backlog = 4096  # Increased backlog for high concurrency

# Worker processes - MAXIMUM for 4 vCPU, 16GB RAM
workers = 12  # 3x CPU cores for maximum performance
worker_class = "sync"
worker_connections = 3000  # Maximum connections per worker
max_requests = 10000  # Higher before restart
max_requests_jitter = 200

# Timeouts - Optimized for high load
timeout = 600  # 10 minutes for long operations
keepalive = 5  # Keep connections alive longer
graceful_timeout = 60  # More time for graceful shutdown

# Memory management
preload_app = True
max_requests_jitter = 50

# Logging
accesslog = "logs/gunicorn_access.log"
errorlog = "logs/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'gbot_web_app'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Performance tuning
worker_tmp_dir = "/dev/shm"  # Use shared memory for worker temp files

# Environment variables
raw_env = [
    'FLASK_ENV=production',
    'PYTHONPATH=/opt/gbot-web-app',
]

# Pre-fork optimization
def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def worker_abort(worker):
    worker.log.info("worker received SIGABRT signal")
