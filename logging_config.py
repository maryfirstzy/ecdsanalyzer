
import logging
import os
from datetime import datetime
import json

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure main application logger
def setup_main_logger():
    """Setup main application logger for all processes"""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    # File handler for all logs
    file_handler = logging.FileHandler('logs/bitcoin_analyzer_full.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler for important messages
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Setup scanner-specific logger
def setup_scanner_logger():
    """Setup dedicated logger for scanning processes"""
    scanner_logger = logging.getLogger('scanner')
    scanner_logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter(
        '%(asctime)s - SCANNER - %(levelname)s - %(message)s'
    )
    
    # Scanner-specific file handler
    scanner_handler = logging.FileHandler('logs/scanner_activity.log')
    scanner_handler.setLevel(logging.DEBUG)
    scanner_handler.setFormatter(formatter)
    
    scanner_logger.addHandler(scanner_handler)
    return scanner_logger

# Setup API logger
def setup_api_logger():
    """Setup dedicated logger for API requests"""
    api_logger = logging.getLogger('api')
    api_logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter(
        '%(asctime)s - API - %(levelname)s - %(message)s'
    )
    
    # API-specific file handler
    api_handler = logging.FileHandler('logs/api_requests.log')
    api_handler.setLevel(logging.DEBUG)
    api_handler.setFormatter(formatter)
    
    api_logger.addHandler(api_handler)
    return api_logger

class AddressAnalysisLogger:
    """Specialized logger for tracking address-specific signature analysis"""
    
    def __init__(self):
        self.log_dir = 'logs/addresses'
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # Setup general address analysis logger
        self.analysis_logger = logging.getLogger('address_analysis')
        self.analysis_logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - ADDRESS_ANALYSIS - %(levelname)s - %(message)s'
        )
        
        analysis_handler = logging.FileHandler('logs/address_analysis.log')
        analysis_handler.setLevel(logging.INFO)
        analysis_handler.setFormatter(formatter)
        
        self.analysis_logger.addHandler(analysis_handler)
    
    def get_address_log_file(self, address: str) -> str:
        """Get the log file path for a specific address"""
        safe_address = address.replace('/', '_').replace('\\', '_')
        return os.path.join(self.log_dir, f"{safe_address}.json")
    
    def log_signature_data(self, address: str, tx_id: str, signatures: list):
        """Log signature data for a specific address"""
        timestamp = datetime.now().isoformat()
        log_file = self.get_address_log_file(address)
        
        # Create signature entry
        signature_entry = {
            'timestamp': timestamp,
            'tx_id': tx_id,
            'address': address,
            'signatures': []
        }
        
        # Process each signature
        for i, sig in enumerate(signatures):
            sig_data = {
                'input_index': sig.get('input_index', i),
                'r': sig.get('r'),
                's': sig.get('s'),
                'z': sig.get('message'),  # message hash
                'r_reused': False,  # Will be determined during comparison
                'potential_nonce_reuse': False
            }
            signature_entry['signatures'].append(sig_data)
        
        # Read existing data
        existing_data = []
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    existing_data = json.load(f)
            except Exception as e:
                self.analysis_logger.error(f"Failed to read existing data for {address}: {e}")
        
        # Check for r-value reuse across all historical signatures
        self._check_r_value_reuse(signature_entry, existing_data)
        
        # Add new entry
        existing_data.append(signature_entry)
        
        # Write back to file
        try:
            with open(log_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
        except Exception as e:
            self.analysis_logger.error(f"Failed to write signature data for {address}: {e}")
        
        # Log summary
        r_reuse_count = sum(1 for sig in signature_entry['signatures'] if sig['r_reused'])
        if r_reuse_count > 0:
            self.analysis_logger.critical(f"🚨 R-VALUE REUSE DETECTED! Address: {address}, TX: {tx_id}, Reused R values: {r_reuse_count}")
            
        self.analysis_logger.info(f"Logged {len(signatures)} signatures for address {address} in TX {tx_id}")
    
    def _check_r_value_reuse(self, new_entry: dict, historical_data: list):
        """Check for r-value reuse between new signatures and historical data"""
        new_signatures = new_entry['signatures']
        
        # Collect all historical r values
        historical_r_values = {}
        for entry in historical_data:
            for sig in entry.get('signatures', []):
                r_val = sig.get('r')
                if r_val:
                    if r_val not in historical_r_values:
                        historical_r_values[r_val] = []
                    historical_r_values[r_val].append({
                        'tx_id': entry['tx_id'],
                        'timestamp': entry['timestamp'],
                        's': sig.get('s'),
                        'z': sig.get('z'),
                        'input_index': sig.get('input_index')
                    })
        
        # Check new signatures against historical data
        for sig in new_signatures:
            r_val = sig.get('r')
            if r_val and r_val in historical_r_values:
                sig['r_reused'] = True
                sig['potential_nonce_reuse'] = True
                sig['reuse_history'] = historical_r_values[r_val]
                
                # Log detailed reuse information
                self.analysis_logger.warning(f"R-value {r_val[:16]}... reused in address {new_entry['address']}")
                for historical_sig in historical_r_values[r_val]:
                    self.analysis_logger.warning(f"  Previous use: TX {historical_sig['tx_id']}, s={historical_sig['s'][:16]}..., z={historical_sig['z'][:16]}...")
                
                # Mark historical entries as reused too
                for entry in historical_data:
                    for historical_sig in entry.get('signatures', []):
                        if historical_sig.get('r') == r_val:
                            historical_sig['r_reused'] = True
                            historical_sig['potential_nonce_reuse'] = True
    
    def get_address_analysis(self, address: str) -> dict:
        """Get comprehensive analysis for a specific address"""
        log_file = self.get_address_log_file(address)
        
        if not os.path.exists(log_file):
            return {
                'address': address,
                'total_transactions': 0,
                'total_signatures': 0,
                'r_reuse_cases': 0,
                'vulnerable_transactions': [],
                'r_value_groups': {}
            }
        
        try:
            with open(log_file, 'r') as f:
                data = json.load(f)
            
            # Analyze the data
            total_transactions = len(data)
            total_signatures = sum(len(entry.get('signatures', [])) for entry in data)
            
            # Group by r values to find reuse patterns
            r_value_groups = {}
            vulnerable_transactions = []
            
            for entry in data:
                tx_has_reuse = False
                for sig in entry.get('signatures', []):
                    r_val = sig.get('r')
                    if r_val:
                        if r_val not in r_value_groups:
                            r_value_groups[r_val] = []
                        r_value_groups[r_val].append({
                            'tx_id': entry['tx_id'],
                            'timestamp': entry['timestamp'],
                            'signature': sig
                        })
                        
                        if sig.get('r_reused'):
                            tx_has_reuse = True
                
                if tx_has_reuse:
                    vulnerable_transactions.append(entry['tx_id'])
            
            # Count actual reuse cases
            r_reuse_cases = sum(1 for r_val, sigs in r_value_groups.items() if len(sigs) > 1)
            
            return {
                'address': address,
                'total_transactions': total_transactions,
                'total_signatures': total_signatures,
                'r_reuse_cases': r_reuse_cases,
                'vulnerable_transactions': vulnerable_transactions,
                'r_value_groups': {r: len(sigs) for r, sigs in r_value_groups.items() if len(sigs) > 1}
            }
            
        except Exception as e:
            self.analysis_logger.error(f"Failed to analyze address {address}: {e}")
            return {'error': str(e)}
    
    def find_nonce_reuse_pairs(self, address: str) -> list:
        """Find specific signature pairs that can be used for private key recovery"""
        log_file = self.get_address_log_file(address)
        
        if not os.path.exists(log_file):
            return []
        
        try:
            with open(log_file, 'r') as f:
                data = json.load(f)
            
            # Group signatures by r value
            r_groups = {}
            for entry in data:
                for sig in entry.get('signatures', []):
                    r_val = sig.get('r')
                    if r_val:
                        if r_val not in r_groups:
                            r_groups[r_val] = []
                        r_groups[r_val].append({
                            'tx_id': entry['tx_id'],
                            'timestamp': entry['timestamp'],
                            'signature': sig
                        })
            
            # Find pairs with different z values (true nonce reuse)
            recovery_pairs = []
            for r_val, sigs in r_groups.items():
                if len(sigs) > 1:
                    # Check all pairs for different z values
                    for i in range(len(sigs)):
                        for j in range(i + 1, len(sigs)):
                            sig1 = sigs[i]['signature']
                            sig2 = sigs[j]['signature']
                            
                            # Only include if z values are different (true nonce reuse)
                            if sig1.get('z') != sig2.get('z'):
                                recovery_pairs.append({
                                    'r': r_val,
                                    'signature1': {
                                        'tx_id': sigs[i]['tx_id'],
                                        'r': sig1.get('r'),
                                        's': sig1.get('s'),
                                        'z': sig1.get('z'),
                                        'input_index': sig1.get('input_index')
                                    },
                                    'signature2': {
                                        'tx_id': sigs[j]['tx_id'],
                                        'r': sig2.get('r'),
                                        's': sig2.get('s'),
                                        'z': sig2.get('z'),
                                        'input_index': sig2.get('input_index')
                                    },
                                    'recovery_potential': 'high'
                                })
            
            return recovery_pairs
            
        except Exception as e:
            self.analysis_logger.error(f"Failed to find nonce reuse pairs for {address}: {e}")
            return []

class KeyRecoveryLogger:
    """Specialized logger for recovered private keys and addresses"""
    
    def __init__(self):
        self.log_file = 'logs/recovered_keys.json'
        self.summary_file = 'logs/key_recovery_summary.log'
        
        # Setup summary logger
        self.summary_logger = logging.getLogger('key_recovery')
        self.summary_logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - KEY_RECOVERY - %(levelname)s - %(message)s'
        )
        
        summary_handler = logging.FileHandler(self.summary_file)
        summary_handler.setLevel(logging.INFO)
        summary_handler.setFormatter(formatter)
        
        self.summary_logger.addHandler(summary_handler)
    
    def log_recovered_key(self, key_data, tx_id=None, recovery_method=None):
        """Log a recovered private key with all details"""
        timestamp = datetime.now().isoformat()
        
        # Create detailed log entry
        log_entry = {
            'timestamp': timestamp,
            'tx_id': tx_id,
            'recovery_method': recovery_method,
            'private_key_hex': key_data.get('private_key_hex'),
            'private_key_decimal': key_data.get('private_key_decimal'),
            'wif_compressed': key_data.get('wif_compressed'),
            'wif_uncompressed': key_data.get('wif_uncompressed'),
            'addresses': key_data.get('addresses', {}),
            'balances': key_data.get('balances', {}),
            'total_balance': key_data.get('total_balance', 0),
            'primary_address': key_data.get('primary_address'),
            'primary_address_type': key_data.get('primary_address_type'),
            'primary_balance': key_data.get('primary_balance', 0)
        }
        
        # Append to JSON log file
        try:
            # Read existing data
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    existing_data = json.load(f)
            else:
                existing_data = []
            
            # Add new entry
            existing_data.append(log_entry)
            
            # Write back to file
            with open(self.log_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
                
        except Exception as e:
            self.summary_logger.error(f"Failed to write to key recovery log: {e}")
        
        # Log summary to text file
        balance_status = "💰 WITH BALANCE" if key_data.get('total_balance', 0) > 0 else "Empty"
        
        self.summary_logger.critical(f"🔑 PRIVATE KEY RECOVERED {balance_status}")
        self.summary_logger.critical(f"TX: {tx_id}")
        self.summary_logger.critical(f"Method: {recovery_method}")
        self.summary_logger.critical(f"Private Key: {key_data.get('private_key_hex', 'N/A')}")
        self.summary_logger.critical(f"Primary Address: {key_data.get('primary_address', 'N/A')}")
        self.summary_logger.critical(f"Total Balance: {key_data.get('total_balance', 0)} BTC")
        
        if key_data.get('total_balance', 0) > 0:
            self.summary_logger.critical(f"🚨 BALANCE FOUND! 🚨")
            self.summary_logger.critical(f"WIF (Compressed): {key_data.get('wif_compressed', 'N/A')}")
            self.summary_logger.critical(f"All addresses with balances:")
            for addr_type, balance_info in key_data.get('balances', {}).items():
                if balance_info.get('balance', 0) > 0:
                    self.summary_logger.critical(f"  {addr_type}: {balance_info['address']} - {balance_info['balance']} BTC")
    
    def get_recovery_stats(self):
        """Get statistics about recovered keys"""
        try:
            if not os.path.exists(self.log_file):
                return {'total_keys': 0, 'keys_with_balance': 0, 'total_balance': 0}
                
            with open(self.log_file, 'r') as f:
                data = json.load(f)
            
            total_keys = len(data)
            keys_with_balance = sum(1 for entry in data if entry.get('total_balance', 0) > 0)
            total_balance = sum(entry.get('total_balance', 0) for entry in data)
            
            return {
                'total_keys': total_keys,
                'keys_with_balance': keys_with_balance,
                'total_balance': total_balance
            }
        except Exception as e:
            self.summary_logger.error(f"Failed to get recovery stats: {e}")
            return {'total_keys': 0, 'keys_with_balance': 0, 'total_balance': 0}

# Initialize loggers
def initialize_all_loggers():
    """Initialize all logging systems"""
    main_logger = setup_main_logger()
    scanner_logger = setup_scanner_logger()
    api_logger = setup_api_logger()
    key_recovery_logger = KeyRecoveryLogger()
    address_analysis_logger = AddressAnalysisLogger()
    
    main_logger.info("🚀 Bitcoin Analyzer logging system initialized")
    main_logger.info(f"Logs directory: {os.path.abspath('logs')}")
    
    return {
        'main': main_logger,
        'scanner': scanner_logger,
        'api': api_logger,
        'key_recovery': key_recovery_logger,
        'address_analysis': address_analysis_logger
    }
import logging
import os
import json
from datetime import datetime
from typing import Dict, Any

def initialize_all_loggers() -> Dict[str, logging.Logger]:
    """Initialize comprehensive logging system for Bitcoin analyzer"""
    
    # Create logs directory if it doesn't exist
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(os.path.join(logs_dir, "addresses"), exist_ok=True)
    
    # Configure formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Main application logger
    main_logger = logging.getLogger('main')
    main_logger.setLevel(logging.INFO)
    
    main_handler = logging.FileHandler(os.path.join(logs_dir, 'bitcoin_analyzer_full.log'))
    main_handler.setFormatter(detailed_formatter)
    main_logger.addHandler(main_handler)
    
    # API requests logger
    api_logger = logging.getLogger('api')
    api_logger.setLevel(logging.INFO)
    
    api_handler = logging.FileHandler(os.path.join(logs_dir, 'api_requests.log'))
    api_handler.setFormatter(detailed_formatter)
    api_logger.addHandler(api_handler)
    
    # Key recovery logger
    key_recovery_logger = logging.getLogger('key_recovery')
    key_recovery_logger.setLevel(logging.INFO)
    
    key_handler = logging.FileHandler(os.path.join(logs_dir, 'key_recovery_summary.log'))
    key_handler.setFormatter(detailed_formatter)
    key_recovery_logger.addHandler(key_handler)
    
    # Scanner activity logger
    scanner_logger = logging.getLogger('scanner')
    scanner_logger.setLevel(logging.INFO)
    
    scanner_handler = logging.FileHandler(os.path.join(logs_dir, 'scanner_activity.log'))
    scanner_handler.setFormatter(simple_formatter)
    scanner_logger.addHandler(scanner_handler)
    
    # Address analysis logger
    address_logger = logging.getLogger('address_analysis')
    address_logger.setLevel(logging.INFO)
    
    address_handler = logging.FileHandler(os.path.join(logs_dir, 'address_analysis.log'))
    address_handler.setFormatter(detailed_formatter)
    address_logger.addHandler(address_handler)
    
    logging.info("🚀 Bitcoin Analyzer logging system initialized")
    logging.info(f"Logs directory: {os.path.abspath(logs_dir)}")
    
    return {
        'main': main_logger,
        'api': api_logger,
        'key_recovery': key_recovery_logger,
        'scanner': scanner_logger,
        'address_analysis': address_logger
    }

class AddressAnalysisLogger:
    """Special logger for tracking address analysis over time"""
    
    def __init__(self):
        self.logs_dir = os.path.join("logs", "addresses")
        os.makedirs(self.logs_dir, exist_ok=True)
    
    def get_address_log_file(self, address: str) -> str:
        """Get log file path for specific address"""
        safe_address = address.replace('/', '_').replace('\\', '_')
        return os.path.join(self.logs_dir, f"{safe_address}.json")
    
    def log_address_analysis(self, address: str, analysis_data: Dict[str, Any]):
        """Log analysis data for an address"""
        log_file = self.get_address_log_file(address)
        
        # Add timestamp
        analysis_data['timestamp'] = datetime.now().isoformat()
        
        # Read existing data
        existing_data = []
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    existing_data = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                existing_data = []
        
        # Append new data
        existing_data.append(analysis_data)
        
        # Write back to file
        with open(log_file, 'w') as f:
            json.dump(existing_data, f, indent=2)
    
    def get_address_analysis(self, address: str) -> Dict[str, Any]:
        """Get historical analysis data for an address"""
        log_file = self.get_address_log_file(address)
        
        if not os.path.exists(log_file):
            return {
                'address': address,
                'analysis_history': [],
                'total_analyses': 0,
                'first_seen': None,
                'last_seen': None
            }
        
        try:
            with open(log_file, 'r') as f:
                data = json.load(f)
            
            return {
                'address': address,
                'analysis_history': data,
                'total_analyses': len(data),
                'first_seen': data[0]['timestamp'] if data else None,
                'last_seen': data[-1]['timestamp'] if data else None
            }
        except (json.JSONDecodeError, FileNotFoundError):
            return {
                'address': address,
                'analysis_history': [],
                'total_analyses': 0,
                'first_seen': None,
                'last_seen': None
            }
    
    def find_nonce_reuse_pairs(self, address: str) -> list:
        """Find potential nonce reuse pairs for an address"""
        analysis = self.get_address_analysis(address)
        
        # Collect all signatures with their r values
        signatures_by_r = {}
        
        for entry in analysis['analysis_history']:
            for sig in entry.get('signatures', []):
                r_val = sig.get('r')
                if r_val:
                    if r_val not in signatures_by_r:
                        signatures_by_r[r_val] = []
                    signatures_by_r[r_val].append({
                        'signature': sig,
                        'timestamp': entry['timestamp'],
                        'tx_id': entry.get('tx_id')
                    })
        
        # Find r values used more than once
        nonce_reuse_pairs = []
        for r_val, sigs in signatures_by_r.items():
            if len(sigs) > 1:
                nonce_reuse_pairs.append({
                    'r_value': r_val,
                    'usage_count': len(sigs),
                    'signatures': sigs,
                    'exploitable': len(set(sig['signature'].get('z', '') for sig in sigs)) > 1
                })
        
        return nonce_reuse_pairs
