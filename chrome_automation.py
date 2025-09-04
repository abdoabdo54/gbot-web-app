import os
import json
import logging
import paramiko
import tempfile
from typing import List, Dict, Optional, Tuple
from undetected_chromedriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AccountManager:
    """Manages remote account retrieval and Chrome automation for login"""
    
    def __init__(self):
        # Server configuration for account retrieval
        self.SERVER_ADDRESS = '162.55.213.50'
        self.SERVER_PORT = 22
        self.USERNAME = 'root'
        self.PASSWORD = 'GkNqzZVbyRmgES46'
        self.REMOTE_DIR = '/home/Accounts/accounts.json'
        
        # Chrome driver instance (thread-safe)
        self._driver = None
        self._driver_lock = threading.Lock()
        
    def retrieve_accounts_from_server(self) -> List[Dict[str, str]]:
        """
        Retrieve accounts from remote server using SSH
        
        Returns:
            List of dictionaries with 'username' and 'password' keys
        """
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Connecting to server {self.SERVER_ADDRESS}:{self.SERVER_PORT}")
            ssh.connect(
                hostname=self.SERVER_ADDRESS,
                port=self.SERVER_PORT,
                username=self.USERNAME,
                password=self.PASSWORD,
                timeout=30
            )
            
            # Read the accounts.json file
            logger.info(f"Reading accounts from {self.REMOTE_DIR}")
            stdin, stdout, stderr = ssh.exec_command(f'cat {self.REMOTE_DIR}')
            
            # Get the file content
            file_content = stdout.read().decode('utf-8').strip()
            error_content = stderr.read().decode('utf-8').strip()
            
            if error_content:
                logger.error(f"SSH error: {error_content}")
                raise Exception(f"Failed to read accounts file: {error_content}")
            
            if not file_content:
                logger.warning("Accounts file is empty")
                return []
            
            # Parse accounts (format: account:password, one per line)
            accounts = []
            for line in file_content.split('\n'):
                line = line.strip()
                if line and ':' in line:
                    parts = line.split(':', 1)  # Split on first colon only
                    if len(parts) == 2:
                        username, password = parts
                        accounts.append({
                            'username': username.strip(),
                            'password': password.strip()
                        })
            
            logger.info(f"Retrieved {len(accounts)} accounts from server")
            return accounts
            
        except Exception as e:
            logger.error(f"Failed to retrieve accounts from server: {str(e)}")
            raise Exception(f"Account retrieval failed: {str(e)}")
        finally:
            try:
                ssh.close()
            except:
                pass
    
    def get_chrome_driver(self) -> Chrome:
        """
        Get or create an undetect Chrome driver instance
        
        Returns:
            Chrome driver instance
        """
        with self._driver_lock:
            if self._driver is None:
                logger.info("Initializing undetect Chrome driver")
                
                # Configure Chrome options for undetect mode
                options = ChromeOptions()
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-blink-features=AutomationControlled')
                
                # Create undetect Chrome driver
                self._driver = Chrome(options=options)
                
                # Execute script to remove webdriver property
                self._driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                
                logger.info("Chrome driver initialized successfully")
            
            return self._driver
    
    def close_chrome_driver(self):
        """Close the Chrome driver instance"""
        with self._driver_lock:
            if self._driver:
                try:
                    self._driver.quit()
                    logger.info("Chrome driver closed")
                except Exception as e:
                    logger.error(f"Error closing Chrome driver: {str(e)}")
                finally:
                    self._driver = None
    
    def login_with_chrome(self, oauth_url: str, username: str, password: str) -> Dict[str, any]:
        """
        Perform login using Chrome automation
        
        Args:
            oauth_url: The OAuth URL to navigate to
            username: Account username/email
            password: Account password
            
        Returns:
            Dictionary with success status and any error messages
        """
        driver = None
        try:
            logger.info(f"Starting Chrome login for account: {username}")
            
            # Get Chrome driver
            driver = self.get_chrome_driver()
            
            # Navigate to OAuth URL
            logger.info(f"Navigating to OAuth URL: {oauth_url}")
            driver.get(oauth_url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Check if we're on Google login page
            current_url = driver.current_url
            logger.info(f"Current URL after navigation: {current_url}")
            
            if 'accounts.google.com' in current_url:
                # Handle Google login
                return self._handle_google_login(driver, username, password)
            else:
                # Handle other login pages
                return self._handle_generic_login(driver, username, password)
                
        except Exception as e:
            logger.error(f"Chrome login failed: {str(e)}")
            return {
                'success': False,
                'error': f"Login automation failed: {str(e)}"
            }
    
    def _handle_google_login(self, driver: Chrome, username: str, password: str) -> Dict[str, any]:
        """Handle Google-specific login flow"""
        try:
            # Wait for email input field
            email_input = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='email'], input[name='identifier']"))
            )
            
            # Enter email
            logger.info("Entering email address")
            email_input.clear()
            email_input.send_keys(username)
            
            # Click Next button
            next_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit'], #identifierNext")
            next_button.click()
            
            # Wait for password input
            password_input = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password'], input[name='password']"))
            )
            
            # Enter password
            logger.info("Entering password")
            password_input.clear()
            password_input.send_keys(password)
            
            # Click Next button
            next_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit'], #passwordNext")
            next_button.click()
            
            # Wait for redirect or success
            time.sleep(3)
            
            # Check for success or error
            current_url = driver.current_url
            logger.info(f"Login completed. Current URL: {current_url}")
            
            if 'oauth-callback' in current_url or 'consent' in current_url:
                return {
                    'success': True,
                    'message': 'Login successful - OAuth flow completed',
                    'current_url': current_url
                }
            elif 'challenge' in current_url or 'verification' in current_url:
                return {
                    'success': True,
                    'message': 'Login successful - Additional verification may be required',
                    'current_url': current_url,
                    'requires_verification': True
                }
            else:
                return {
                    'success': True,
                    'message': 'Login completed',
                    'current_url': current_url
                }
                
        except TimeoutException:
            return {
                'success': False,
                'error': 'Timeout waiting for login elements'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Google login failed: {str(e)}'
            }
    
    def _handle_generic_login(self, driver: Chrome, username: str, password: str) -> Dict[str, any]:
        """Handle generic login forms"""
        try:
            # Look for common username/email input fields
            username_selectors = [
                "input[type='email']",
                "input[name='email']",
                "input[name='username']",
                "input[name='user']",
                "input[id*='email']",
                "input[id*='username']",
                "input[id*='user']"
            ]
            
            username_input = None
            for selector in username_selectors:
                try:
                    username_input = WebDriverWait(driver, 2).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    break
                except TimeoutException:
                    continue
            
            if not username_input:
                return {
                    'success': False,
                    'error': 'Could not find username/email input field'
                }
            
            # Enter username
            logger.info("Entering username/email")
            username_input.clear()
            username_input.send_keys(username)
            
            # Look for password field
            password_selectors = [
                "input[type='password']",
                "input[name='password']",
                "input[name='pass']",
                "input[id*='password']",
                "input[id*='pass']"
            ]
            
            password_input = None
            for selector in password_selectors:
                try:
                    password_input = WebDriverWait(driver, 2).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    break
                except TimeoutException:
                    continue
            
            if not password_input:
                return {
                    'success': False,
                    'error': 'Could not find password input field'
                }
            
            # Enter password
            logger.info("Entering password")
            password_input.clear()
            password_input.send_keys(password)
            
            # Look for submit button
            submit_selectors = [
                "button[type='submit']",
                "input[type='submit']",
                "button:contains('Login')",
                "button:contains('Sign In')",
                "button:contains('Submit')"
            ]
            
            submit_button = None
            for selector in submit_selectors:
                try:
                    submit_button = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except NoSuchElementException:
                    continue
            
            if submit_button:
                submit_button.click()
            
            # Wait for redirect
            time.sleep(3)
            
            current_url = driver.current_url
            logger.info(f"Generic login completed. Current URL: {current_url}")
            
            return {
                'success': True,
                'message': 'Generic login completed',
                'current_url': current_url
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Generic login failed: {str(e)}'
            }
    
    def get_current_page_info(self) -> Dict[str, any]:
        """Get current page information from Chrome driver"""
        try:
            driver = self.get_chrome_driver()
            return {
                'current_url': driver.current_url,
                'title': driver.title,
                'page_source_length': len(driver.page_source)
            }
        except Exception as e:
            return {
                'error': f'Failed to get page info: {str(e)}'
            }

# Global instance
account_manager = AccountManager()
