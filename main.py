
#!/usr/bin/env python3
"""
Main entry point for Bitcoin ECDSA Analyzer
"""

from app import app
from logging_config import initialize_all_loggers

if __name__ == '__main__':
    # Initialize comprehensive logging system
    loggers = initialize_all_loggers()
    logger = loggers['main']
    
    logger.info("🚀 Starting Bitcoin ECDSA Analyzer with comprehensive logging")
    logger.info("📁 Log files location: logs/")
    logger.info("🔑 Recovered keys will be logged to: logs/recovered_keys.json")
    logger.info("📊 All activities logged to: logs/bitcoin_analyzer_full.log")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
