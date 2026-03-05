"""
Logging filter to redact sensitive data
Prevents credentials, tokens, PII, and secrets from appearing in logs

Security Features:
- Redacts private keys and certificates
- Masks tokens and API keys
- Partial masking of email addresses
- Credit card number protection
- Password redaction
"""
import re
import os
import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Tuple, List


class SensitiveDataFilter(logging.Filter):
    """
    Logging filter that automatically redacts sensitive information.
    
    Applies pattern matching to log messages and arguments to replace
    sensitive data with safe placeholders.
    """
    
    # Patterns for sensitive data detection and replacement
    PATTERNS: List[Tuple[re.Pattern, str]] = [
        # Private keys (PEM format)
        (
            re.compile(r'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----', re.DOTALL),
            '***PRIVATE_KEY_REDACTED***'
        ),
        
        # Private key in JSON
        (
            re.compile(r'"private_key":\s*"[^"]*"'),
            '"private_key": "***REDACTED***"'
        ),
        (
            re.compile(r"'private_key':\s*'[^']*'"),
            "'private_key': '***REDACTED***'"
        ),
        
        # Service account credentials (common patterns)
        (
            re.compile(r'"client_email":\s*"[^"]*"'),
            '"client_email": "***REDACTED***"'
        ),
        (
            re.compile(r'"client_id":\s*"[^"]*"'),
            '"client_id": "***REDACTED***"'
        ),
        
        # Tokens (various formats)
        (
            re.compile(r'"token":\s*"[^"]*"'),
            '"token": "***REDACTED***"'
        ),
        (
            re.compile(r'"access_token":\s*"[^"]*"'),
            '"access_token": "***REDACTED***"'
        ),
        (
            re.compile(r'"refresh_token":\s*"[^"]*"'),
            '"refresh_token": "***REDACTED***"'
        ),
        (
            re.compile(r'"id_token":\s*"[^"]*"'),
            '"id_token": "***REDACTED***"'
        ),
        (
            re.compile(r'"credential_token":\s*"[^"]*"'),
            '"credential_token": "***REDACTED***"'
        ),
        (
            re.compile(r'"csrf_token":\s*"[^"]*"'),
            '"csrf_token": "***REDACTED***"'
        ),
        
        # Bearer tokens
        (
            re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'),
            'Bearer ***REDACTED***'
        ),
        
        # API Keys (various patterns)
        (
            re.compile(r'(api[_-]?key|apikey)[\s:=]+["\']?([A-Za-z0-9\-_]{20,})["\']?', re.IGNORECASE),
            r'\1: ***REDACTED***'
        ),
        (
            re.compile(r'"api_key":\s*"[^"]*"'),
            '"api_key": "***REDACTED***"'
        ),
        
        # Passwords and secrets
        (
            re.compile(r'(password|passwd|pwd|secret)[\s:=]+["\']?([^"\'\s]{3,})["\']?', re.IGNORECASE),
            r'\1: ***REDACTED***'
        ),
        (
            re.compile(r'"password":\s*"[^"]*"'),
            '"password": "***REDACTED***"'
        ),
        
        # Email addresses (partial masking - keep domain)
        (
            re.compile(r'\b([A-Za-z0-9._%+-]{1,3})[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b'),
            r'\1***@\2'
        ),
        
        # Credit card numbers (full masking)
        (
            re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            '****-****-****-****'
        ),
        
        # Authorization headers
        (
            re.compile(r'"Authorization":\s*"[^"]*"'),
            '"Authorization": "***REDACTED***"'
        ),
        (
            re.compile(r"'Authorization':\s*'[^']*'"),
            "'Authorization': '***REDACTED***'"
        ),
        
        # JWT tokens (they often appear in logs)
        (
            re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            'eyJ***.eyJ***.***'
        ),
        
        # AWS keys
        (
            re.compile(r'AKIA[0-9A-Z]{16}'),
            'AKIA***REDACTED***'
        ),
        
        # Google API keys (various lengths)
        (
            re.compile(r'AIza[0-9A-Za-z_-]{20,}'),
            'AIza***REDACTED***'
        ),
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log record to redact sensitive information.
        
        Args:
            record: The log record to filter
            
        Returns:
            bool: Always True (we modify but don't suppress records)
        """
        # Filter the main message
        if isinstance(record.msg, str):
            record.msg = self._redact_sensitive_data(record.msg)
        
        # Filter message arguments
        if record.args:
            if isinstance(record.args, dict):
                # Dict-style args
                filtered_args = {}
                for key, value in record.args.items():
                    if isinstance(value, str):
                        filtered_args[key] = self._redact_sensitive_data(value)
                    else:
                        filtered_args[key] = value
                record.args = filtered_args
            elif isinstance(record.args, tuple):
                # Tuple-style args
                filtered_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        filtered_args.append(self._redact_sensitive_data(arg))
                    else:
                        filtered_args.append(arg)
                record.args = tuple(filtered_args)
        
        return True
    
    def _redact_sensitive_data(self, text: str) -> str:
        """
        Apply all redaction patterns to a text string.
        
        Args:
            text: The text to redact
            
        Returns:
            str: The redacted text
        """
        for pattern, replacement in self.PATTERNS:
            text = pattern.sub(replacement, text)
        return text


def configure_safe_logging(log_level: int = logging.INFO) -> None:
    """
    Configure logging with sensitive data filtering.
    
    This should be called early in the application startup to ensure
    all logs are filtered from the beginning.
    
    Args:
        log_level: The logging level (default: INFO)
    """
    # Configure basic logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add sensitive data filter to all handlers
    filter_instance = SensitiveDataFilter()
    for handler in logging.root.handlers:
        handler.addFilter(filter_instance)

    # Add file handler if LOG_DIR is set (for packaged app) or fallback to home dir
    log_dir = os.getenv('LOG_DIR')
    if not log_dir:
        # Fallback to home directory for easier debugging on macOS
        log_dir = os.path.expanduser("~")
        
    if log_dir:
        try:
            log_file = os.path.join(log_dir, 'gcp_scanner_backend.log')
            file_handler = RotatingFileHandler(
                log_file, 
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            file_handler.addFilter(filter_instance)
            logging.getLogger().addHandler(file_handler)
            logging.getLogger(__name__).info(f"Logging to file: {log_file}")
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to setup file logging: {e}")
    
    logger = logging.getLogger(__name__)
    logger.info("Logging configured with sensitive data filtering")


# Test function to verify filter is working
def test_filter():
    """
    Test the sensitive data filter with sample data.
    Used for verification during development.
    """
    configure_safe_logging()
    logger = logging.getLogger(__name__)
    
    # These should all be redacted
    logger.info("Testing private key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----")
    logger.info('Testing token: {"access_token": "ya29.a0AfH6SMBx1234567890"}')
    logger.info("Testing email: john.doe@example.com")
    logger.info("Testing API key: api_key=AIzaSyD1234567890abcdefghijklmnop")
    logger.info("Testing password: password=MySecretPass123!")
    logger.info("Testing credit card: 4532-1234-5678-9010")
    logger.info("Testing Bearer token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    
    logger.info("✅ Filter test complete. Check output above - sensitive data should be redacted.")


if __name__ == "__main__":
    # Run test when module is executed directly
    test_filter()
