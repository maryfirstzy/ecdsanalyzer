
#!/usr/bin/env python3
"""
Log Viewer Utility for Bitcoin Analyzer
View and analyze logs from the Bitcoin ECDSA analyzer
"""

import json
import os
from datetime import datetime
import argparse

def view_recovered_keys():
    """View all recovered private keys"""
    log_file = 'logs/recovered_keys.json'
    
    if not os.path.exists(log_file):
        print("No recovered keys log file found.")
        return
    
    try:
        with open(log_file, 'r') as f:
            keys_data = json.load(f)
        
        print(f"\n🔑 RECOVERED PRIVATE KEYS SUMMARY")
        print("=" * 60)
        print(f"Total Keys Recovered: {len(keys_data)}")
        
        keys_with_balance = [k for k in keys_data if k.get('total_balance', 0) > 0]
        total_balance = sum(k.get('total_balance', 0) for k in keys_data)
        
        print(f"Keys with Balance: {len(keys_with_balance)}")
        print(f"Total BTC Value: {total_balance:.8f} BTC")
        print("=" * 60)
        
        for i, key_data in enumerate(keys_data, 1):
            timestamp = key_data.get('timestamp', 'Unknown')
            tx_id = key_data.get('tx_id', 'Unknown')
            method = key_data.get('recovery_method', 'Unknown')
            balance = key_data.get('total_balance', 0)
            primary_addr = key_data.get('primary_address', 'Unknown')
            
            balance_indicator = "💰" if balance > 0 else "🗿"
            
            print(f"\n{balance_indicator} Key #{i}")
            print(f"  Timestamp: {timestamp}")
            print(f"  Transaction: {tx_id}")
            print(f"  Method: {method}")
            print(f"  Primary Address: {primary_addr}")
            print(f"  Total Balance: {balance:.8f} BTC")
            
            if balance > 0:
                print(f"  🚨 HAS BALANCE! 🚨")
                print(f"  Private Key: {key_data.get('private_key_hex', 'N/A')}")
                print(f"  WIF: {key_data.get('wif_compressed', 'N/A')}")
    
    except Exception as e:
        print(f"Error reading recovered keys log: {e}")

def view_scanner_activity():
    """View scanner activity logs"""
    log_file = 'logs/scanner_activity.log'
    
    if not os.path.exists(log_file):
        print("No scanner activity log found.")
        return
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        print(f"\n📊 SCANNER ACTIVITY SUMMARY")
        print("=" * 60)
        print(f"Total Log Entries: {len(lines)}")
        
        # Show last 20 entries
        print("\nLast 20 Scanner Activities:")
        for line in lines[-20:]:
            print(line.strip())
    
    except Exception as e:
        print(f"Error reading scanner activity log: {e}")

def view_api_requests():
    """View API request logs"""
    log_file = 'logs/api_requests.log'
    
    if not os.path.exists(log_file):
        print("No API requests log found.")
        return
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        print(f"\n🌐 API REQUESTS SUMMARY")
        print("=" * 60)
        print(f"Total API Requests: {len(lines)}")
        
        # Show last 10 requests
        print("\nLast 10 API Requests:")
        for line in lines[-10:]:
            print(line.strip())
    
    except Exception as e:
        print(f"Error reading API requests log: {e}")

def main():
    parser = argparse.ArgumentParser(description='Bitcoin Analyzer Log Viewer')
    parser.add_argument('--keys', action='store_true', help='View recovered private keys')
    parser.add_argument('--scanner', action='store_true', help='View scanner activity')
    parser.add_argument('--api', action='store_true', help='View API requests')
    parser.add_argument('--all', action='store_true', help='View all logs')
    
    args = parser.parse_args()
    
    if args.all or not any([args.keys, args.scanner, args.api]):
        view_recovered_keys()
        view_scanner_activity()
        view_api_requests()
    else:
        if args.keys:
            view_recovered_keys()
        if args.scanner:
            view_scanner_activity()
        if args.api:
            view_api_requests()

if __name__ == "__main__":
    main()
