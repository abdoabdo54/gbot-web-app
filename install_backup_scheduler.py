#!/usr/bin/env python3
"""
Installation script for automated backup scheduler
Installs required dependencies and initializes the backup scheduler
"""

import subprocess
import sys
import os

def install_dependencies():
    """Install required dependencies for backup scheduler"""
    print("🔧 Installing backup scheduler dependencies...")
    
    try:
        # Install APScheduler
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'APScheduler==3.10.4'])
        print("✅ APScheduler installed successfully")
        
        # Install other dependencies if needed
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ All dependencies installed successfully")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def test_backup_scheduler():
    """Test if backup scheduler can be imported"""
    print("🧪 Testing backup scheduler import...")
    
    try:
        from backup_scheduler import BackupScheduler
        print("✅ Backup scheduler module imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import backup scheduler: {e}")
        return False

def main():
    """Main installation function"""
    print("🚀 GBot Automated Backup Scheduler Installation")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists('app.py'):
        print("❌ Error: app.py not found. Please run this script from the GBot project directory.")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Installation failed. Please check the error messages above.")
        sys.exit(1)
    
    # Test import
    if not test_backup_scheduler():
        print("❌ Import test failed. Please check the error messages above.")
        sys.exit(1)
    
    print("\n🎉 Automated Backup Scheduler Installation Complete!")
    print("\n📋 What's been installed:")
    print("   • APScheduler 3.10.4 - Background task scheduler")
    print("   • Automated backup system with daily scheduling")
    print("   • Backup management interface in Settings page")
    
    print("\n🕐 Backup Schedule:")
    print("   • Daily at 12:00 AM (midnight)")
    print("   • Daily at 12:00 PM (noon)")
    
    print("\n🚀 Next Steps:")
    print("   1. Restart your GBot application")
    print("   2. Go to Settings page (admin only)")
    print("   3. Click 'Start Scheduler' to enable automated backups")
    print("   4. Use 'Test Scheduler' to verify it's working")
    
    print("\n📁 Backup files will be stored in: ./backups/")
    print("   • Manual backups: gbot_db_backup_manual_YYYYMMDD_HHMMSS.sql")
    print("   • Automated backups: gbot_db_backup_auto_midnight_YYYYMMDD_HHMMSS.sql")
    print("   • Automated backups: gbot_db_backup_auto_noon_YYYYMMDD_HHMMSS.sql")

if __name__ == '__main__':
    main()
