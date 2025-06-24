
import json
import datetime
import logging
from typing import Dict, List, Any
import os

logger = logging.getLogger(__name__)

class RecoveryLogger:
    """Centralized logging system for all private key recoveries"""
    
    def __init__(self):
        self.log_dir = "recovery_logs"
        self._ensure_log_directory()
    
    def _ensure_log_directory(self):
        """Ensure log directory exists"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def log_recovery(self, recovery_data: Dict, source: str = "unknown"):
        """Log a private key recovery with full details"""
        try:
            timestamp = datetime.datetime.now()
            timestamp_str = timestamp.strftime('%Y%m%d_%H%M%S_%f')
            
            # Enhanced recovery data with metadata
            enhanced_data = {
                'recovery_id': f"{source}_{timestamp_str}",
                'timestamp': timestamp.isoformat(),
                'source_scanner': source,
                'recovery_data': recovery_data,
                'log_version': '1.0'
            }
            
            # Log to main recovery file (JSON)
            main_log_file = os.path.join(self.log_dir, 'all_recoveries.json')
            with open(main_log_file, 'a') as f:
                json.dump(enhanced_data, f, indent=2)
                f.write('\n')
            
            # Log to source-specific file
            source_log_file = os.path.join(self.log_dir, f'{source}_recoveries.json')
            with open(source_log_file, 'a') as f:
                json.dump(enhanced_data, f, indent=2)
                f.write('\n')
            
            # Log to human-readable summary
            self._log_human_readable(enhanced_data)
            
            # Log to CSV for easy analysis
            self._log_to_csv(enhanced_data)
            
            # Console logging with full details
            self._console_log_recovery(enhanced_data)
            
        except Exception as e:
            logger.error(f"Error in recovery logging: {e}")
    
    def _log_human_readable(self, enhanced_data: Dict):
        """Log in human-readable format"""
        summary_file = os.path.join(self.log_dir, 'recovery_summary.txt')
        
        recovery = enhanced_data['recovery_data']
        timestamp = enhanced_data['timestamp']
        source = enhanced_data['source_scanner']
        
        with open(summary_file, 'a') as f:
            f.write(f"\n{'='*150}\n")
            f.write(f"PRIVATE KEY RECOVERY - {timestamp}\n")
            f.write(f"{'='*150}\n")
            f.write(f"Recovery ID: {enhanced_data['recovery_id']}\n")
            f.write(f"Source Scanner: {source}\n")
            f.write(f"Recovery Method: {recovery.get('recovery_method', 'unknown')}\n")
            f.write(f"Transaction/Source: {recovery.get('transaction_id', recovery.get('source', 'unknown'))}\n")
            f.write(f"\n🔑 PRIVATE KEY INFORMATION:\n")
            f.write(f"Hex: {recovery.get('private_key_hex', 'N/A')}\n")
            f.write(f"Decimal: {recovery.get('private_key_decimal', 'N/A')}\n")
            f.write(f"WIF (Compressed): {recovery.get('wif_compressed', 'N/A')}\n")
            f.write(f"WIF (Uncompressed): {recovery.get('wif_uncompressed', 'N/A')}\n")
            
            f.write(f"\n💰 BALANCE INFORMATION:\n")
            f.write(f"Primary Address: {recovery.get('primary_address', 'N/A')}\n")
            f.write(f"Primary Address Type: {recovery.get('primary_address_type', 'N/A')}\n")
            f.write(f"Primary Balance: {recovery.get('primary_balance', 0):.8f} BTC\n")
            f.write(f"Total Balance (All Formats): {recovery.get('total_balance', 0):.8f} BTC\n")
            
            f.write(f"\n🏠 ALL ADDRESS FORMATS:\n")
            for addr_type, addr_info in recovery.get('all_balances', {}).items():
                balance = addr_info.get('balance', 0)
                address = addr_info.get('address', 'N/A')
                status = "💰 HAS FUNDS" if balance > 0 else "💸 EMPTY"
                f.write(f"  {addr_type}: {address} - {balance:.8f} BTC {status}\n")
            
            if 'calculation_details' in recovery:
                f.write(f"\n🧮 CALCULATION DETAILS:\n")
                calc_details = recovery['calculation_details']
                for key, value in calc_details.items():
                    f.write(f"  {key}: {value}\n")
            
            if 'signatures_used' in recovery:
                f.write(f"\n📊 SIGNATURES USED:\n")
                for i, sig in enumerate(recovery['signatures_used']):
                    f.write(f"  Signature {i+1}:\n")
                    f.write(f"    R: {sig.get('r', 'N/A')}\n")
                    f.write(f"    S: {sig.get('s', 'N/A')}\n")
                    f.write(f"    Message: {sig.get('message', 'N/A')}\n")
                    if 'input_index' in sig:
                        f.write(f"    Input Index: {sig['input_index']}\n")
            
            f.write(f"{'='*150}\n")
    
    def _log_to_csv(self, enhanced_data: Dict):
        """Log to CSV for spreadsheet analysis"""
        csv_file = os.path.join(self.log_dir, 'recoveries.csv')
        
        recovery = enhanced_data['recovery_data']
        
        # Check if file exists and write header if needed
        write_header = not os.path.exists(csv_file)
        
        with open(csv_file, 'a') as f:
            if write_header:
                f.write("timestamp,recovery_id,source_scanner,recovery_method,private_key_hex,wif_compressed,primary_address,primary_balance,total_balance,transaction_source\n")
            
            # Write data row
            f.write(f"{enhanced_data['timestamp']},")
            f.write(f"{enhanced_data['recovery_id']},")
            f.write(f"{enhanced_data['source_scanner']},")
            f.write(f"{recovery.get('recovery_method', 'unknown')},")
            f.write(f"{recovery.get('private_key_hex', 'N/A')},")
            f.write(f"{recovery.get('wif_compressed', 'N/A')},")
            f.write(f"{recovery.get('primary_address', 'N/A')},")
            f.write(f"{recovery.get('primary_balance', 0):.8f},")
            f.write(f"{recovery.get('total_balance', 0):.8f},")
            f.write(f"{recovery.get('transaction_id', recovery.get('source', 'unknown'))}\n")
    
    def _console_log_recovery(self, enhanced_data: Dict):
        """Enhanced console logging"""
        recovery = enhanced_data['recovery_data']
        
        logger.critical("🚨" * 50)
        logger.critical("🎉 PRIVATE KEY RECOVERY LOGGED! 🎉")
        logger.critical("🚨" * 50)
        logger.critical(f"💻 Scanner: {enhanced_data['source_scanner']}")
        logger.critical(f"🕒 Time: {enhanced_data['timestamp']}")
        logger.critical(f"🔍 Method: {recovery.get('recovery_method', 'unknown')}")
        logger.critical(f"🔑 Private Key: {recovery.get('private_key_hex', 'N/A')}")
        logger.critical(f"🏠 Primary Address: {recovery.get('primary_address', 'N/A')}")
        logger.critical(f"💰 Primary Balance: {recovery.get('primary_balance', 0):.8f} BTC")
        logger.critical(f"💎 Total Balance: {recovery.get('total_balance', 0):.8f} BTC")
        logger.critical(f"📁 Recovery ID: {enhanced_data['recovery_id']}")
        logger.critical("🚨" * 50)
    
    def get_recovery_stats(self) -> Dict:
        """Get statistics about all recoveries"""
        try:
            main_log_file = os.path.join(self.log_dir, 'all_recoveries.json')
            if not os.path.exists(main_log_file):
                return {'total_recoveries': 0, 'total_balance': 0, 'scanners': {}}
            
            stats = {
                'total_recoveries': 0,
                'total_balance': 0,
                'scanners': {},
                'recovery_methods': {},
                'recoveries_with_balance': 0
            }
            
            with open(main_log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            recovery = json.loads(line)
                            stats['total_recoveries'] += 1
                            
                            source = recovery.get('source_scanner', 'unknown')
                            if source not in stats['scanners']:
                                stats['scanners'][source] = 0
                            stats['scanners'][source] += 1
                            
                            recovery_data = recovery.get('recovery_data', {})
                            method = recovery_data.get('recovery_method', 'unknown')
                            if method not in stats['recovery_methods']:
                                stats['recovery_methods'][method] = 0
                            stats['recovery_methods'][method] += 1
                            
                            total_balance = recovery_data.get('total_balance', 0)
                            stats['total_balance'] += total_balance
                            
                            if total_balance > 0:
                                stats['recoveries_with_balance'] += 1
                                
                        except json.JSONDecodeError:
                            continue
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting recovery stats: {e}")
            return {'error': str(e)}

# Global recovery logger instance
recovery_logger = RecoveryLogger()
