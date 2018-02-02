from bitcoin_tools import CFG
from binascii import hexlify, unhexlify
from bitcoin_tools.analysis.status import FEE_STEP
from bitcoin_tools.analysis.status.utils import check_multisig, get_min_input_size, roundup_rate, check_multisig_type, txout_decompress, decompress_script
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

		dec_script = decompress_script(out["out_type"], outdata)
		#print dec_script

		#script = unhexlify(dec_script)
		script = dec_script
                if out["out_type"] == 0:
                    # P2PKH
                    num_bytes  = dec_script[4:6]
                    public_key = dec_script[6:6+20]
                    z          = b'\00'+public_key
                    z          = base58.b58encode_check(z)
                    #print("p2pkh,{},{},{}".format(amount, z, hexlify(script)))
                    #print("p2pkh,{},{},{}".format(amount, z, dec_script))
                    print("p2pkh,{},{},{}".format(amount, '' , dec_script))
		    #print "num_bytes=" + str(num_bytes)
                    #print "script=" + str(script)
	            #print "pk=" + str(public_key)
		    #exit()

                elif out["out_type"] == 1:
                    # P2SH
                    num_bytes  = script[1]
                    public_key = script[2:22]
                    z          = b'\05'+public_key
                    z          = base58.b58encode_check(z)
                    #print("p2sh,{},{},{}".format(amount, z, hexlify(script)))
                    print("p2sh,{},{},{}".format(amount, z, dec_script))
                elif ( outdata[0:1] == b'5') and outdata[-2:] == b'ae':
                    #public_key = script[2:22]
                    #z          = b'\00'+public_key
                    #z          = base58.b58encode_check(z)
                    #print("multisig,{},{},{}".format(amount, z, hexlify(script)))
                    print("multisig,{},,{}".format(amount, dec_script))
                elif outdata[-2:] == b'ac' and (outdata[0:2] == b'41' or outdata[0:2] == b'21'):
                    #print len(data), len(script)
                    # P2PK
                    if outdata[0:2] == b'41':
                        offset = 65
                    elif outdata[0:2] == b'21':
                        offset  = 33

                    #pubkey = script[1:1+offset]
                    #pubkeyhash = ripemd160(sha256(pubkey).digest())

                    #z          = '\00'+pubkeyhash
                    #z          = base58.b58encode_check(z)
                    #print("p2pk,{},{},{}".format(amount, z, hexlify(script)))
                    print("p2pk,{},{},{}".format(amount, '', dec_script)
                else:
                    print("unkown,{},,{},{},{}".format( amount, dec_script))

		# TEMP
		#exit()

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

OP_DUP = chr(0x76)
OP_HASH160 = chr(0xa9)
OP_EQUALVERIFY = chr(0x88)
OP_CHECKSIG = chr(0xac)
OP_EQUAL = chr(0x87)

def decompress_script(script_type,script_bytes):
    """ Takes CScript as stored in leveldb and returns it in uncompressed form
    (de)compression scheme is defined in bitcoin/src/compressor.cpp

    :param script_type: first byte of script data (out_type in decode_utxo)
    :type script_type: int
    :param script_bytes: raw script bytes hexlified (data in decode_utxo)
    :type script_bytes: str
    :return: the decompressed CScript
    :rtype: str
    """

    #print script_type
    data = unhexlify(script_bytes)
    if script_type == 0:
        assert len(data) == 20
        data = OP_DUP + OP_HASH160 + chr(20) + data + \
            OP_EQUALVERIFY + OP_CHECKSIG

    elif script_type == 1:
        assert len(data) == 20
        data = OP_HASH160 + chr(20) + data + OP_EQUAL

    elif script_type == 2 or script_type == 3:
        data = data[1:]
        assert len(data) == 32
        #data = chr(33) + script_type + data + OP_CHECKSIG
        data = chr(99) + chr(99) + data + OP_CHECKSIG

    elif script_type == 4 or script_type == 5:
        data = data[1:]
        assert len(data) == 32

        comp_pubkey = chr(script_type - 2) + data
        pubkey = secp256k1.PublicKey(
            comp_pubkey, raw=True).serialize(compressed=False)

        data = chr(65) + pubkey + OP_CHECKSIG

    else:
        assert len(data) == script_type - 6
        data = hexlify(data)

    return hexlify(data)

