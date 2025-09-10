#!/usr/bin/env python3
"""
Automated Database Backup Scheduler
Handles daily automated backups at 12 AM and midnight
"""

import os
import logging
import threading
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
import atexit

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BackupScheduler:
    def __init__(self, app=None):
        self.app = app
        self.scheduler = None
        self.is_running = False
        self.backup_jobs = []
        
    def init_app(self, app):
        """Initialize the scheduler with Flask app context"""
        self.app = app
        self.setup_scheduler()
        
    def setup_scheduler(self):
        """Setup the background scheduler"""
        try:
            self.scheduler = BackgroundScheduler()
            self.scheduler.add_listener(self.job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
            
            # Register cleanup function
            atexit.register(lambda: self.shutdown())
            
            logger.info("Backup scheduler initialized")
        except Exception as e:
            logger.error(f"Failed to initialize backup scheduler: {e}")
    
    def job_listener(self, event):
        """Handle job execution events"""
        if event.exception:
            logger.error(f"Backup job failed: {event.exception}")
        else:
            logger.info(f"Backup job completed successfully: {event.job_id}")
    
    def create_automated_backup(self, backup_type="daily"):
        """Create an automated backup"""
        try:
            with self.app.app_context():
                from app import create_database_backup_internal
                
                # Create backup with default settings
                result = create_database_backup_internal(
                    format='sql',
                    include_data='full',
                    automated=True,
                    backup_type=backup_type
                )
                
                if result.get('success'):
                    logger.info(f"Automated {backup_type} backup created: {result.get('filename')}")
                    return result
                else:
                    logger.error(f"Automated {backup_type} backup failed: {result.get('error')}")
                    return result
                    
        except Exception as e:
            logger.error(f"Error creating automated backup: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_scheduler(self):
        """Start the backup scheduler"""
        if self.scheduler and not self.is_running:
            try:
                # Add daily backup at 12:00 AM (midnight)
                self.scheduler.add_job(
                    func=self.create_automated_backup,
                    trigger=CronTrigger(hour=0, minute=0),
                    args=['midnight'],
                    id='daily_backup_midnight',
                    name='Daily Backup at Midnight',
                    replace_existing=True
                )
                
                # Add daily backup at 12:00 PM (noon)
                self.scheduler.add_job(
                    func=self.create_automated_backup,
                    trigger=CronTrigger(hour=12, minute=0),
                    args=['noon'],
                    id='daily_backup_noon',
                    name='Daily Backup at Noon',
                    replace_existing=True
                )
                
                self.scheduler.start()
                self.is_running = True
                
                logger.info("Backup scheduler started - Daily backups at 12:00 AM and 12:00 PM")
                
                # Log next run times
                midnight_job = self.scheduler.get_job('daily_backup_midnight')
                noon_job = self.scheduler.get_job('daily_backup_noon')
                
                if midnight_job:
                    logger.info(f"Next midnight backup: {midnight_job.next_run_time}")
                if noon_job:
                    logger.info(f"Next noon backup: {noon_job.next_run_time}")
                    
            except Exception as e:
                logger.error(f"Failed to start backup scheduler: {e}")
    
    def stop_scheduler(self):
        """Stop the backup scheduler"""
        if self.scheduler and self.is_running:
            try:
                self.scheduler.shutdown()
                self.is_running = False
                logger.info("Backup scheduler stopped")
            except Exception as e:
                logger.error(f"Error stopping backup scheduler: {e}")
    
    def get_scheduler_status(self):
        """Get current scheduler status"""
        if not self.scheduler:
            return {
                'running': False,
                'jobs': [],
                'error': 'Scheduler not initialized'
            }
        
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                'id': job.id,
                'name': job.name,
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                'trigger': str(job.trigger)
            })
        
        return {
            'running': self.is_running,
            'jobs': jobs
        }
    
    def shutdown(self):
        """Shutdown the scheduler"""
        self.stop_scheduler()

# Global scheduler instance
backup_scheduler = BackupScheduler()

def init_backup_scheduler(app):
    """Initialize the backup scheduler with Flask app"""
    backup_scheduler.init_app(app)
    backup_scheduler.start_scheduler()

def get_backup_scheduler():
    """Get the global backup scheduler instance"""
    return backup_scheduler
