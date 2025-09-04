import paramiko
import json
import logging
import os
import tempfile
from typing import List, Dict, Optional, Tuple
import undetected_chromedriver as uc
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import time
import threading
from queue import Queue
import re

class RemoteAccountManager:
    """Manages remote account retrieval and Chrome automation for login"""
    
    def __init__(self):
        # Server configuration for account retrieval
        self.SERVER_ADDRESS = '162.55.213.50'
        self.SERVER_PORT = 22
        self.USERNAME = 'root'
        self.PASSWORD = 'GkNqzZVbyRmgES46'
        self.REMOTE_DIR = '/home/Accounts/accounts.json'
        
        # Chrome driver configuration
        self.chrome_options = None
        self.driver = None
        self.login_queue = Queue()
        self.max_concurrent_logins = 3  # Default, will be updated from UI
        
    def retrieve_accounts_from_server(self) -> List[Dict[str, str]]:
        """
        Retrieve accounts from remote server via SFTP
        
        Returns:
            List of dictionaries with 'account' and 'password' keys
        """
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to server
            ssh.connect(
                hostname=self.SERVER_ADDRESS,
                port=self.SERVER_PORT,
                username=self.USERNAME,
                password=self.PASSWORD,
                timeout=30
            )
            
            # Create SFTP client
            sftp = ssh.open_sftp()
            
            # Download accounts file to temporary location
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_path = temp_file.name
            
            try:
                sftp.get(self.REMOTE_DIR, temp_path)
                
                # Read and parse accounts
                accounts = []
                with open(temp_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                            
                        # Parse account:password format
                        if ':' in line:
                            parts = line.split(':', 1)  # Split on first colon only
                            if len(parts) == 2:
                                account, password = parts
                                accounts.append({
                                    'account': account.strip(),
                                    'password': password.strip()
                                })
                            else:
                                logging.warning(f"Invalid format at line {line_num}: {line}")
                        else:
                            logging.warning(f"Missing password separator at line {line_num}: {line}")
                
                logging.info(f"Successfully retrieved {len(accounts)} accounts from server")
                return accounts
                
            finally:
                # Clean up temporary file
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                sftp.close()
                ssh.close()
                
        except Exception as e:
            logging.error(f"Failed to retrieve accounts from server: {e}")
            return []
    
    def setup_chrome_driver(self, headless: bool = False) -> Optional[uc.Chrome]:
        """
        Setup undetect Chrome driver with optimal settings
        
        Args:
            headless: Whether to run in headless mode
            
        Returns:
            Chrome driver instance or None if setup fails
        """
        try:
            options = uc.ChromeOptions()
            
            # Basic options
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-plugins')
            options.add_argument('--disable-web-security')
            options.add_argument('--allow-running-insecure-content')
            options.add_argument('--disable-features=VizDisplayCompositor')
            options.add_argument('--disable-ipc-flooding-protection')
            
            # User agent
            options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            # Window size
            options.add_argument('--window-size=1920,1080')
            
            if headless:
                options.add_argument('--headless')
            
            # Create driver
            driver = uc.Chrome(options=options)
            
            # Execute script to remove webdriver property
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            self.chrome_options = options
            return driver
            
        except Exception as e:
            logging.error(f"Failed to setup Chrome driver: {e}")
            return None
    
    def login_to_google_account(self, account: str, password: str, oauth_url: str) -> Dict[str, any]:
        """
        Login to Google account using undetect Chrome driver
        
        Args:
            account: Email address
            password: Account password
            oauth_url: OAuth URL to navigate to after login
            
        Returns:
            Dictionary with success status and details
        """
        driver = None
        try:
            # Setup driver
            driver = self.setup_chrome_driver(headless=False)
            if not driver:
                return {'success': False, 'error': 'Failed to setup Chrome driver'}
            
            # Navigate to Google login
            driver.get('https://accounts.google.com/signin')
            
            # Wait for page to load
            wait = WebDriverWait(driver, 20)
            
            # Find and fill email field
            try:
                email_field = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, 'input[type="email"], input[name="identifier"]')))
                email_field.clear()
                email_field.send_keys(account)
                
                # Click Next button
                next_button = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], #identifierNext')
                next_button.click()
                
                # Wait for password field
                password_field = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, 'input[type="password"], input[name="password"]')))
                password_field.clear()
                password_field.send_keys(password)
                
                # Click Next button for password
                password_next = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], #passwordNext')
                password_next.click()
                
                # Wait for login to complete (check for successful redirect or error)
                time.sleep(5)
                
                # Check if login was successful
                current_url = driver.current_url
                if 'myaccount.google.com' in current_url or 'accounts.google.com' in current_url:
                    # Login successful, navigate to OAuth URL
                    driver.get(oauth_url)
                    
                    # Wait for OAuth page to load
                    time.sleep(3)
                    
                    # Check if we need to authorize
                    try:
                        authorize_button = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')))
                        authorize_button.click()
                        
                        # Wait for authorization to complete
                        time.sleep(5)
                        
                        # Check if we got redirected to callback URL
                        final_url = driver.current_url
                        if 'oauth-callback' in final_url or 'code=' in final_url:
                            return {
                                'success': True,
                                'message': 'Login and authorization completed successfully',
                                'final_url': final_url
                            }
                        else:
                            return {
                                'success': True,
                                'message': 'Login successful, authorization may be pending',
                                'final_url': final_url
                            }
                            
                    except TimeoutException:
                        # No authorization button found, might already be authorized
                        return {
                            'success': True,
                            'message': 'Login successful, no authorization required',
                            'final_url': driver.current_url
                        }
                        
                else:
                    # Check for error messages
                    error_elements = driver.find_elements(By.CSS_SELECTOR, '.error, .error-message, [role="alert"]')
                    if error_elements:
                        error_text = error_elements[0].text
                        return {'success': False, 'error': f'Login failed: {error_text}'}
                    else:
                        return {'success': False, 'error': 'Login failed: Unknown error'}
                        
            except TimeoutException as e:
                return {'success': False, 'error': f'Timeout waiting for login elements: {str(e)}'}
            except Exception as e:
                return {'success': False, 'error': f'Login error: {str(e)}'}
                
        except Exception as e:
            return {'success': False, 'error': f'Chrome automation error: {str(e)}'}
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
    
    def process_login_queue(self, max_concurrent: int = 3):
        """
        Process login queue with concurrency control
        
        Args:
            max_concurrent: Maximum number of concurrent login processes
        """
        active_threads = []
        
        while True:
            # Clean up finished threads
            active_threads = [t for t in active_threads if t.is_alive()]
            
            # Start new threads if we have capacity and items in queue
            while len(active_threads) < max_concurrent and not self.login_queue.empty():
                login_data = self.login_queue.get()
                thread = threading.Thread(
                    target=self._process_single_login,
                    args=(login_data,)
                )
                thread.start()
                active_threads.append(thread)
            
            # Sleep if no work to do
            if not active_threads and self.login_queue.empty():
                time.sleep(1)
            else:
                time.sleep(0.5)
    
    def _process_single_login(self, login_data: Dict):
        """
        Process a single login request
        
        Args:
            login_data: Dictionary containing account, password, and oauth_url
        """
        try:
            result = self.login_to_google_account(
                login_data['account'],
                login_data['password'],
                login_data['oauth_url']
            )
            
            # Store result for retrieval
            login_data['result'] = result
            
        except Exception as e:
            login_data['result'] = {
                'success': False,
                'error': f'Thread error: {str(e)}'
            }
    
    def add_login_to_queue(self, account: str, password: str, oauth_url: str) -> str:
        """
        Add a login request to the queue
        
        Args:
            account: Email address
            password: Account password
            oauth_url: OAuth URL
            
        Returns:
            Queue ID for tracking
        """
        queue_id = f"login_{int(time.time())}_{account}"
        login_data = {
            'id': queue_id,
            'account': account,
            'password': password,
            'oauth_url': oauth_url,
            'timestamp': time.time(),
            'status': 'queued'
        }
        
        self.login_queue.put(login_data)
        return queue_id

# Global instance
account_manager = RemoteAccountManager()
