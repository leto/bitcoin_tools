from bitcoin_tools import CFG
from binascii import hexlify, unhexlify
from bitcoin_tools.analysis.status import FEE_STEP
from bitcoin_tools.analysis.status.utils import check_multisig, get_min_input_size, roundup_rate, check_multisig_type, txout_decompress
import ujson
from subprocess import call
from os import remove
import base58
import secp256k1
import hashlib


def transaction_dump(fin_name, fout_name, version=0.15):
    # Transaction dump

    if version < 0.15:

        # Input file
        fin = open(CFG.data_path + fin_name, 'r')
        # Output file
        fout = open(CFG.data_path + fout_name, 'w')

        for line in fin:
            data = ujson.loads(line[:-1])

            utxo = data['value']
            total_value = sum([out["amount"] for out in utxo.get("outs")])
            result = {"tx_id": data["key"],
                      "num_utxos": len(utxo.get("outs")),
                      "total_value": total_value,
                      "total_len": data["len"],
                      "height": utxo["height"],
                      "coinbase": utxo["coinbase"],
                      "version": utxo["version"]}

            fout.write(ujson.dumps(result) + '\n')

        fout.close()
        fin.close()

    else:

        # Sort the decoded utxo data by transaction id.
        call(["sort", CFG.data_path + fin_name, "-o", CFG.data_path + str(version) + '/sorted_decoded_utxos.json'])

        # Set the input and output files
        fin = open(CFG.data_path + str(version) + '/sorted_decoded_utxos.json', 'r')
        fout = open(CFG.data_path + fout_name, 'w')

        # Initial definition
        tx = dict()

        # Read the ordered file and aggregate the data by transaction.
        for line in fin:
            data = ujson.loads(line[:-1])
            utxo = data['value']

            # If the read line contains information of the same transaction we are analyzing we add it to our dictionary
            if utxo.get('tx_id') == tx.get('tx_id'):
                tx['num_utxos'] += 1
                tx['total_value'] += utxo.get('outs')[0].get('amount')
                tx['total_len'] += data['len']

            # Otherwise, we save the transaction data to the output file and start aggregating the next transaction data
            else:
                # Save previous transaction data
                if tx:
                    fout.write(ujson.dumps(tx) + '\n')

                # Create the new transaction
                tx['tx_id'] = utxo.get('tx_id')
                tx['num_utxos'] = 1
                tx['total_value'] = utxo.get('outs')[0].get('amount')
                tx['total_len'] = data['len']
                tx['height'] = utxo["height"]
                tx['coinbase'] = utxo["coinbase"]
                tx['version'] = None

        fin.close()
        fout.close()
        remove(CFG.data_path + str(version) + '/sorted_decoded_utxos.json')


def utxo_dump(fin_name, fout_name, version=0.15, count_p2sh=False, non_std_only=False):
    # UTXO dump

    # Input file
    fin = open(CFG.data_path + fin_name, 'r')
    # Output file
    fout = open(CFG.data_path + fout_name, 'w')

    # Standard UTXO types
    std_types = [0, 1, 2, 3, 4, 5]

    for line in fin:
        data = ujson.loads(line[:-1])
        utxo = data['value']
        if version < 0.15:
            tx_id = data["key"]
        else:
            tx_id = utxo.get('tx_id')
        for out in utxo.get("outs"):
            # Checks whether we are looking for every type of UTXO or just for non-standard ones.
            if not non_std_only or (non_std_only and out["out_type"] not in std_types
                                    and not check_multisig(out['data'])):

                # Calculates the dust threshold for every UTXO value and every fee per byte ratio between min and max.
                min_size = get_min_input_size(out, utxo["height"], count_p2sh)
                dust = 0
                np = 0

                if min_size > 0:
                    raw_dust = out["amount"] / float(3 * min_size)
                    raw_np = out["amount"] / float(min_size)

                    dust = roundup_rate(raw_dust, FEE_STEP)
                    np = roundup_rate(raw_np, FEE_STEP)

                # Adds multisig type info
                if out["out_type"] in [0, 1, 2, 3, 4, 5]:
                    non_std_type = "std"
                else:
                    non_std_type = check_multisig_type(out["data"])

                # Builds the output dictionary
                result = {"tx_id": tx_id,
                          "tx_height": utxo["height"],
                          "utxo_data_len": len(out["data"]) / 2,
                          "dust": dust,
                          "non_profitable": np,
                          "non_std_type": non_std_type}

                amt = out["amount"]
                amount =  "%d.%08d" %  (amt / 100000000 , amt % 100000000 )
                utxo_data_len = len(out["data"]) / 2

                outdata = out["data"]
                script  = unhexlify(outdata)
                if out["out_type"] == 0:
                    # P2PKH
                    num_bytes  = script[2]
                    public_key = script[3:23]
                    z          = b'\00'+public_key
                    z          = base58.b58encode_check(z)
                    print("p2pkh,{},{},{}".format(amount, z, hexlify(script)))
                if out["out_type"] == 1:
                    # P2SH
                    num_bytes  = script[1]
                    public_key = script[2:22]
                    z          = b'\05'+public_key
                    z          = base58.b58encode_check(z)
                    print("p2sh,{},{},{}".format(amount, z, hexlify(script)))
                elif( outdata[0:1] == b'5') and outdata[-2:] == b'ae':
                    #public_key = script[2:22]
                    #z          = b'\00'+public_key
                    #z          = base58.b58encode_check(z)
                    #print("multisig,{},{},{}".format(amount, z, hexlify(script)))
                    print("multisig,{},,{}".format(amount, hexlify(script)))
                elif outdata[-2:] == b'ac' and (outdata[0:2] == b'41' or outdata[0:2] == b'21'):
                    #print len(data), len(script)
                    # P2PK
                    if outdata[0:2] == b'41':
                        offset = 65
                    elif outdata[0:2] == b'21':
                        offset  = 33

                    pubkey = script[1:1+offset]
                    pubkeyhash = ripemd160(sha256(pubkey).digest())

                    z          = '\00'+pubkeyhash
                    z          = base58.b58encode_check(z)
                    print("p2pk,{},{},{}".format(amount, z, hexlify(script)))
                else:
                    print("unkown,{},,{},{},{}".format( amount, hexlify(script), utxo_data_len, out["out_type"]))

                # Index added at the end when updated the result with the out, since the index is not part of the
                # encoded data anymore (coin) but of the entry identifier (outpoint), we add it manually.
                if version >= 0.15:
                    result['index'] = utxo['index']
                    result['register_len'] = data['len']

                # Updates the dictionary with the remaining data from out, and stores it in disk.
                result.update(out)
                fout.write(ujson.dumps(result) + '\n')

    fin.close()
    fout.close()

def ripemd160(st):
    r = hashlib.new('ripemd160')
    r.update(st)
    return r.digest()
