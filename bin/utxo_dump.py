#!/usr/bin/env python

from bitcoin_tools.analysis.status.data_dump import utxo_dump
from bitcoin_tools.analysis.status.utils import parse_ldb

# Set the version of the Bitcoin Core you are using (which defines the chainstate format)
# and the IO files.
version = 0.11
f_utxos = "decoded_utxos.csv"
f_parsed_utxos = "parsed_utxos.csv"

# Parse all the data in the chainstate.
parse_ldb(f_utxos, version=version)
# Parses transactions and utxos from the dumped data.
utxo_dump(f_utxos, f_parsed_utxos, version=version)
