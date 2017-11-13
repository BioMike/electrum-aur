#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import threading, time, Queue, os, sys, shutil
from util import user_dir, appdata_dir, print_error, print_msg
from bitcoin import *
import hashlib
import sqlite3
import math

try:
    from ltc_scrypt import getPoWHash as getPoWScryptHash
except ImportError:
    print_msg("Warning: ltc_scrypt not available, using fallback")
    from scrypt import scrypt_1024_1_1_80 as getPoWScryptHash

try:
    import groestl_hash
except ImportError:
    print_msg("Warning: groestl_hash not available, please install it")
    raise

try:
    import py_bca_skein
except ImportError:
    print_msg("Warning: py_bca_skein not available, please install it")
    raise

try:
    import qubit_hash
except ImportError:
    print_msg("Warning: qubit_hash not available, please install it")
    raise


class Blockchain(threading.Thread):

    def __init__(self, config, network):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.network = network
        self.lock = threading.Lock()
        self.local_height = 0
        self.running = False
        #self.headers_url = 'http://digibytewiki.com/blockchain_headers'    URL is broken.
        self.set_local_height()
        self.queue = Queue.Queue()
        header_db_file = sqlite3.connect(self.db_path())
        header_db = header_db_file.cursor()
        try:
            first_header = header_db.execute('SELECT * FROM headers WHERE height = 0')
        except Exception:
            header_db.execute('CREATE TABLE headers (header, algo, height int UNIQUE)')
        header_db_file.commit()
        header_db_file.close()

    
    def height(self):
        return self.local_height


    def stop(self):
        with self.lock: self.running = False


    def is_running(self):
        with self.lock: return self.running


    def run(self):
        self.init_headers_file()
        self.set_local_height()
        print_error( "blocks:", self.local_height )

        with self.lock:
            self.running = True

        while self.is_running():

            try:
                result = self.queue.get()
            except Queue.Empty:
                continue

            if not result: continue

            i, header = result
            if not header: continue
            
            height = header.get('block_height')

            if height <= self.local_height:
                continue

            if height > self.local_height + 50:
                if not self.get_and_verify_chunks(i, header, height):
                    continue

            if height > self.local_height:
                # get missing parts from interface (until it connects to my chain)
                chain = self.get_chain( i, header )

                # skip that server if the result is not consistent
                if not chain: 
                    print_error('e')
                    continue
                
                # verify the chain
                if self.verify_chain( chain ):
                    print_error("height:", height, i.server)
                    for header in chain:
                        self.save_header(header)
                else:
                    print_error("error", i.server)
                    # todo: dismiss that server
                    continue


            self.network.new_blockchain_height(height, i)


    def verify_chain(self, chain):

        first_header = chain[0]
        prev_header = self.read_header(first_header.get('block_height') -1)

        for header in chain:

            height = header.get('block_height')

            prev_hash = self.hash_header(prev_header)
            version = header.get('version')
            if version <= 2:
                algo = "scrypt"
                pow_hash = self.pow_hash_scrypt_header(header)
            elif version == 514:
                algo = "sha256d"
                pow_hash = self.pow_hash_sha_header(header)
                _hash = pow_hash
            elif version == 1026:
                algo = "groestl"
                pow_hash = self.pow_hash_groestl_header(header)
            elif version == 1538:
                algo = "skein"
                pow_hash = self.pow_hash_skein_header(header)
            elif version == 2050:
                algo = "qubit"
                pow_hash = self.pow_hash_qubit_header(header)
            else:
                print_error( "error unknown block version")

            bits, target = self.get_target(height, algo)

            try:
                assert prev_hash == header.get('prev_block_hash')
                assert bits == header.get('bits')
                assert int('0x'+pow_hash,16) < target
            except Exception:
                return False

            raw_header = self.header_to_string(header)

            # Store the block to the database (currently very inefficient, but correct on how to do it).
            header_db_file = sqlite3.connect(self.db_path())
            header_db = header_db_file.cursor()
            header_db.execute('''INSERT OR REPLACE INTO headers VALUES ('%s', '%s', '%s')''' % (raw_header, algo, str(height)))
            header_db_file.commit()
            header_db_file.close()

            prev_header = header

        return True



    def verify_chunk(self, index, hexdata):
        # This is utterly broken, we're not going to be picky
        # on validating most values now.
        print_error("verify_chunk %i" % (index, ))

        data = hexdata.decode('hex')
        height = index*2016
        num = len(data)/80

        if index == 0:
            previous_hash = ("0"*64)
        else:
            previous_header = self.read_header(height-1)
            if previous_header is None: raise
            previous_hash = self.hash_header(previous_header)

        for i in xrange(num):
            height = index*2016 + i
            raw_header = data[i*80:(i+1)*80]
            header = self.header_from_string(raw_header)

            _hash = self.hash_header(header)
            version = header.get('version')
            if version <= 2:
                algo = "scrypt"
                pow_hash = self.pow_hash_scrypt_header(header)
            elif version == 514:
                algo = "sha256d"
                pow_hash = self.pow_hash_sha_header(header)
                _hash = pow_hash
            elif version == 1026:
                algo = "groestl"
                pow_hash = self.pow_hash_groestl_header(header)
            elif version == 1538:
                algo = "skein"
                pow_hash = self.pow_hash_skein_header(header)
            elif version == 2050:
                algo = "qubit"
                pow_hash = self.pow_hash_qubit_header(header)
            else:
                print_error( "error unknown block version")

            bits, target = self.get_target(height, algo)

            # Print the block
            print_error("height: %i\tversion: %i" % (height, version))
            print_error("hash: %i %s" % (height, _hash))
            print_error("PoW hash: %s" % (pow_hash, ))
            print_error("header: %s\n" % (header, ))

            assert previous_hash == header.get('prev_block_hash')
            assert bits == header.get('bits')
            assert int('0x'+pow_hash,16) < target

            # Store the block to the database (currently very inefficient, but correct on how to do it).
            header_db_file = sqlite3.connect(self.db_path())
            header_db = header_db_file.cursor()
            header_db.execute('''INSERT OR REPLACE INTO headers VALUES ('%s', '%s', '%s')''' % (raw_header.encode('hex'), algo, str(height)))
            header_db_file.commit()
            header_db_file.close()

            previous_header = header
            previous_hash = _hash

        self.save_chunk(index, data)
        print_error("validated chunk %d"%height)


    def header_to_string(self, res):
        s = int_to_hex(res.get('version'),4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')),4) \
            + int_to_hex(int(res.get('bits')),4) \
            + int_to_hex(int(res.get('nonce')),4)
        return s


    def header_from_string(self, s):
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        return h

    def hash_header(self, header):
        # Hash originates from bitcoin.py
        return rev_hex(Hash(self.header_to_string(header).decode('hex')).encode('hex'))

    def pow_hash_scrypt_header(self, header):
        return rev_hex(getPoWScryptHash(self.header_to_string(header).decode('hex')).encode('hex'))

    def pow_hash_sha_header(self,header):
        return self.hash_header(header)

    def pow_hash_skein_header(self,header):
        return rev_hex(py_bca_skein.getPoWHash(self.header_to_string(header).decode('hex')).encode('hex'))

    def pow_hash_groestl_header(self,header):
        return rev_hex(groestl_hash.getGroestlMyrHash(self.header_to_string(header).decode('hex'), len(self.header_to_string(header))).encode('hex'))

    def pow_hash_qubit_header(self,header):
        return rev_hex(qubit_hash.getPoWHash(self.header_to_string(header).decode('hex')).encode('hex'))

    def path(self):
        return os.path.join( self.config.path, 'blockchain_headers')

    def db_path(self):
        return os.path.join(self.config.path, 'headers.db')


    def init_headers_file(self):
        filename = self.path()
        if os.path.exists(filename):
            return

        # The self.headers_url location is not hosting the headers any more.
        # Disable the download and create the default file to be populated.
        #try:
        #    import urllib, socket
        #    socket.setdefaulttimeout(30)
        #    print_error("downloading ", self.headers_url )
        #    urllib.urlretrieve(self.headers_url, filename)
        #    print_error("done.")
        #except Exception:
        print_error( "download failed. creating file", filename )
        open(filename,'wb+').close()

    def save_chunk(self, index, chunk):
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(index*2016*80)
        h = f.write(chunk)
        f.close()
        self.set_local_height()

    def save_header(self, header):
        data = self.header_to_string(header).decode('hex')
        assert len(data) == 80
        height = header.get('block_height')
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(height*80)
        h = f.write(data)
        f.close()
        self.set_local_height()


    def set_local_height(self):
        name = self.path()
        if os.path.exists(name):
            h = os.path.getsize(name)/80 - 1
            if self.local_height != h:
                self.local_height = h


    def read_header(self, block_height):
        name = self.path()
        if os.path.exists(name):
            f = open(name,'rb')
            f.seek(block_height*80)
            h = f.read(80)
            f.close()
            if len(h) == 80:
                h = self.header_from_string(h)
                return h 


    def get_target(self, height, algo):

        if height <= 135:
            # Return default values below block 135.
            return 0x1E0FFFFF, 0x00000FFFFF000000000000000000000000000000000000000000000000000000
        if height <= 5400:
            # Return original diff algorithm calculated values.
            bits, target = self.target_orig(height)
            return bits, target
        if height <= 225000:
            # Return KGW calculated values.
            bits, target = self.target_kgw(height)
            return bits, target
        else:
            # Return multi-algo calculated values.
            bits, target = self.target_multi(height, algo)
            return bits, target

    def bits_to_target(self, bits):
        # bits to target
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x1e):
            raise BaseException("First part of bits should be in [0x03, 0x1e]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
        target = bitsBase << (8 * (bitsN-3))
        return(target)

    def target_to_bits(self, target):
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        bits = bitsN << 24 | bitsBase
        return(bits)

    def target_orig(self, height):
        max_target = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        # Only recalulate new bits once every 8 blocks.
        if((height % 8) != 0):
           previous_header = self.get_block_by_height((height - 1))
           bits = previous_header.get('bits')
           target = self.bits_to_target(bits)
           return bits, target
        first = self.get_block_by_height((height - 9))
        last = self.get_block_by_height((height - 1))

        # bits to target
        bits = last.get('bits')
        target = self.bits_to_target(bits)
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 8 * 10 * 60
        nActualTimespanMax = ((nTargetTimespan*75)//50)
        nActualTimespanMin = ((nTargetTimespan*50)//75)

        if (nActualTimespan < nActualTimespanMin):
            nActualTimespan = nActualTimespanMin
        if (nActualTimespan > nActualTimespanMax):
            nActualTimespan = nActualTimespanMax
        new_target_calc = min(max_target, ((target * nActualTimespan) // nTargetTimespan))
        # convert new target to bits (and to new_target)
        new_bits = self.target_to_bits(new_target_calc)
        new_target = self.bits_to_target(new_bits)
        return new_bits, new_target

    def target_kgw(self, height):
        max_target = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        blocktargetspacing = 300
        pastblocksmin = 144
        pastblocksmax = 4032
        pastblockmass = 0

        blockreading_height = height - 1
        blocklastsolved = self.get_block_by_height(blockreading_height)
        blockreading = blocklastsolved

        # Bail check

        # Main mass calculation
        i = 1

        while (blockreading and blockreading_height > 0):
            if pastblocksmax > 0 and i > pastblocksmax:
                break;

            pastblockmass += 1

            if i == 1:
                PastDifficultyAverage = self.bits_to_target(blockreading.get('bits'))
            else:
                PastDifficultyAverage = ((self.bits_to_target(blockreading.get('bits')) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev

            # Set PastDifficultyAveragePrev
            PastDifficultyAveragePrev = PastDifficultyAverage

            PastRateActualSeconds = blocklastsolved.get('timestamp') - blockreading.get('timestamp')
            PastRateTargetSeconds = blocktargetspacing * pastblockmass
            PastRateAdjustmentRatio = 1.0
            if PastRateActualSeconds < 0:
                PastRateActualSeconds = 0
            if PastRateActualSeconds != 0 and PastRateTargetSeconds != 0:
                PastRateAdjustmentRatio = float(PastRateTargetSeconds) / float(PastRateActualSeconds)

            EventHorizonDeviation = 1 + (0.7084 * pow((pastblockmass/144.0), -1.228))
            EventHorizonDeviationFast = EventHorizonDeviation
            EventHorizonDeviationSlow = 1 / EventHorizonDeviation

            if pastblockmass >= pastblocksmin:
                if (PastRateAdjustmentRatio <= EventHorizonDeviationSlow) or (PastRateAdjustmentRatio >= EventHorizonDeviationFast):
                    #assert(BlockReading);
                    break

            # BlockReading previous validation check.
            if ((blockreading_height - 1) < 0):
                #assert(BlockReading);
                break

            # Lower blockreading to previous block.
            blockreading_height -= 1
            blockreading = self.get_block_by_height(blockreading_height)
            i += 1

        # Calculate new bits
        if (PastRateActualSeconds != 0 and PastRateTargetSeconds != 0):
            new_target_calc = min(max_target, ((PastDifficultyAverage * PastRateActualSeconds) // PastRateTargetSeconds))
        else:
            new_target_calc = PastDifficultyAverage

        # convert new target to bits (and to new_target)
        new_bits = self.target_to_bits(new_target_calc)
        new_target = self.bits_to_target(new_bits)
        return new_bits, new_target

    def target_multi(self, height, algo):
        if algo is 'qubit':
            max_bits = 0x1E03FFFF
        elif algo is 'sha256d':
            max_bits = 0x1D00FFFF
        else:
            max_bits = 0x1E01FFFF
        max_target = self.bits_to_target(max_bits)
        nAveragingTargetTimespan = 10 * 5 * 61
        minActualTimespan = nAveragingTargetTimespan * (100 - 8) / 100
        maxActualTimespan = nAveragingTargetTimespan * (100 + 16) / 100
        lastheight = height - 1
        firstheight = lastheight - 50
        first = self.get_block_by_height((firstheight))
        prev_algo_height = self.getlastblockindexforalgo(height, algo)
        if prev_algo_height is None:
            #print_error("Returning default diff")
            return max_bits, max_target
        prev_algo = self.get_block_by_height(prev_algo_height)

        # Limit adjustment step
        # Use medians to prevent time-warp attacks
        actualTimespan = self.getmediantimepast(lastheight) - self.getmediantimepast(firstheight)

        # The next part is split in two, due to a difference in how
        # integer divisions work between c++ and python, c++ gravitates towards
        # 0, while python always floors. This is a problem for negative results
        # of the division.
        actualTimespan = (actualTimespan - nAveragingTargetTimespan)/4.0
        if actualTimespan < 0:
            actualTimespan = int(math.ceil(actualTimespan))
        elif actualTimespan > 0:
            actualTimespan = int(math.floor(actualTimespan))

        actualTimespan = nAveragingTargetTimespan + actualTimespan
        if (actualTimespan < minActualTimespan):
            actualTimespan = minActualTimespan
        if (actualTimespan > maxActualTimespan):
            actualTimespan = maxActualTimespan

        # Global retarget
        target = self.bits_to_target(prev_algo.get('bits'))
        new_target_calc = (target * actualTimespan) // nAveragingTargetTimespan

        # Per-algo retarget
        adjustments = prev_algo_height + 5 - 1 - lastheight
        if adjustments > 0:
            while adjustments:
                new_target_calc = ((new_target_calc * 100) // (100 + 4))
                adjustments -= 1
        elif adjustments < 0:
            while adjustments:
                new_target_calc = ((new_target_calc * (100 + 4)) // 100 )
                adjustments += 1
        new_target_calc = min(max_target, new_target_calc)
        new_bits = self.target_to_bits(new_target_calc)
        new_target = self.bits_to_target(new_bits)
        return new_bits, new_target


    def request_header(self, i, h, queue):
        print_error("requesting header %d from %s"%(h, i.server))
        i.send_request({'method':'blockchain.block.get_header', 'params':[h]}, queue)

    def retrieve_request(self, queue):
        while True:
            try:
                ir = queue.get(timeout=1)
            except Queue.Empty:
                print_error('blockchain: request timeout')
                continue
            i, r = ir
            result = r['result']
            return result

    def get_chain(self, interface, final_header):

        header = final_header
        chain = [ final_header ]
        requested_header = False
        queue = Queue.Queue()

        while self.is_running():

            if requested_header:
                header = self.retrieve_request(queue)
                if not header: return
                chain = [ header ] + chain
                requested_header = False

            height = header.get('block_height')
            previous_header = self.read_header(height -1)
            if not previous_header:
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            # verify that it connects to my chain
            prev_hash = self.hash_header(previous_header)
            if prev_hash != header.get('prev_block_hash'):
                print_error("reorg")
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            else:
                # the chain is complete
                return chain


    def get_and_verify_chunks(self, i, header, height):

        queue = Queue.Queue()
        min_index = (self.local_height + 1)/2016
        max_index = (height + 1)/2016
        n = min_index
        while n < max_index + 1:
            print_error( "Requesting chunk:", n )
            i.send_request({'method':'blockchain.block.get_chunk', 'params':[n]}, queue)
            r = self.retrieve_request(queue)
            try:
                self.verify_chunk(n, r)
                n = n + 1
            except Exception:
                print_error('Verify chunk failed!')
                n = n - 1
                if n < 0:
                    return False

        return True

    def get_block_by_height(self, height):
        header_db_file = sqlite3.connect(self.db_path())
        header_db = header_db_file.cursor()
        header_db.execute("SELECT header FROM headers WHERE height=?", (height, ))
        header = header_db.fetchone()[0]
        header_data = self.header_from_string(header.decode('hex'))
        header_db_file.commit()
        header_db_file.close()
        return(header_data)

    def getlastblockindexforalgo(self, height, algo):
        header_db_file = sqlite3.connect(self.db_path())
        header_db = header_db_file.cursor()
        header_db.execute("SELECT height FROM headers WHERE height<? AND algo=? ORDER BY height DESC LIMIT 1", (height, algo))
        result = header_db.fetchone()
        if result is not None:
            height_new = result[0]
            #print_error(height_new)
            header_db_file.commit()
            header_db_file.close()
        else:
            height_new = None
        return(height_new)

    def getmediantimepast(self, height):
        medianTimespan = 11
        timelist = []
        while(medianTimespan > 0):
            # get times from height to height - 11
            block = self.get_block_by_height(height)
            timelist.append(block.get('timestamp'))
            medianTimespan -= 1
            height -= 1
        # sort times
        timelist.sort()
        # return index 6 (start counting at 0!)
        return(timelist[5])
    
    
    