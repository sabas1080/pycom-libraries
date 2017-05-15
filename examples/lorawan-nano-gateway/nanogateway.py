""" LoPy Nano Gateway class """

import os
import binascii
from binascii import unhexlify
import random
import sys
import json
import time
import errno
import _thread
import socket
import time
import datetime
from threading import Timer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


PROTOCOL_VERSION = '\x02'

PUSH_DATA = '\x00'
PUSH_ACK  = '\x01'
PULL_DATA = '\x02'
PULL_ACK  = '\x04'
PULL_RESP = '\x03'

TX_ERR_NONE = "NONE"
TX_ERR_TOO_LATE = "TOO_LATE"
TX_ERR_TOO_EARLY = "TOO_EARLY"
TX_ERR_COLLISION_PACKET = "COLLISION_PACKET"
TX_ERR_COLLISION_BEACON = "COLLISION_BEACON"
TX_ERR_TX_FREQ = "TX_FREQ"
TX_ERR_TX_POWER = "TX_POWER"
TX_ERR_GPS_UNLOCKED = "GPS_UNLOCKED"

STAT_PK = {"stat": {"time": "", "lati": 0,
                    "long": 0, "alti": 0,
                    "rxnb": 0, "rxok": 0,
                    "rxfw": 0, "ackr": 100.0,
                    "dwnb": 0, "txnb": 0}}

RX_PK = {"rxpk": [{"time": "", "tmst": 0,
                   "chan": 0, "rfch": 0,
                   "freq": 9, "stat": 1,
                   "modu": "LORA", "datr": "SF7BW125",
                   "codr": "4/5", "rssi": 0,
                   "lsnr": 0, "size": 0,
                   "data": ""}]}

TX_ACK_PK = {"txpk_ack":{"error":""}}

#(timestamp, rssi, snr, sf)
class stats:
   timestamp = 0
   rssi = 0
   snr = 0
   sf = 8

UP_LINK = 0
DOWN_LINK = 1

AppSKey = '271E403DF4225EEF7E90836494A5B345'
dev_addr = '000015E4'
payload_hex= '686f6c61' #hola in hex

class NanoGateway:

    def __init__(self, id, frequency, datarate, ssid, password, server, port, ntp='pool.ntp.org', ntp_period=3600):
        self.id = id
        self.frequency = frequency
        self.sf = self._dr_to_sf(datarate)
        self.ssid = ssid
        self.password = password
        self.server = server
        self.port = port
        self.ntp = ntp
        self.ntp_period = ntp_period

        self.rxnb = 0
        self.rxok = 0
        self.rxfw = 0
        self.dwnb = 0
        self.txnb = 0

        self.stat_alarm = None
        self.pull_alarm = None
        self.uplink_alarm = None

        self.udp_lock = _thread.allocate_lock()

        self.lora = None
        self.lora_sock = None

    def start(self):

        self._make_node_data()

        # Get the server IP and create an UDP socket
        self.server_ip = socket.getaddrinfo(self.server, self.port)[0][-1]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)

        # Push the first time immediatelly
        self._push_data(self._make_stat_packet())

        # Create the alarms
        #self.stat_alarm = Timer.Alarm(handler=lambda t: self._push_data(self._make_stat_packet()), s=60, periodic=True)

        #self.pull_alarm = Timer.Alarm(handler=lambda u: self._pull_data(), s=25, periodic=True)

        # Start the UDP receive thread
        #_thread.start_new_thread(self._udp_thread, ())

        # Initialize LoRa in LORA mode
        #self.lora = LoRa(mode=LoRa.LORA, frequency=self.frequency, bandwidth=LoRa.BW_125KHZ, sf=self.sf,
        #                 preamble=8, coding_rate=LoRa.CODING_4_5, tx_iq=True)
        # Create a raw LoRa socket
        #self.lora_sock = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
        #self.lora_sock.setblocking(False)
        #self.lora_tx_done = False

        #self.lora.callback(trigger=(LoRa.RX_PACKET_EVENT | LoRa.TX_PACKET_EVENT), handler=self._lora_cb)
        #Dato de Nodo recibido
        self._lora_cb(10)

    def stop(self):
        # TODO: Check how to stop the NTP sync
        # TODO: Create a cancel method for the alarm
        # TODO: kill the UDP thread
        self.sock.close()

    def _dr_to_sf(self, dr):
        sf = dr[2:4]
        if sf[1] not in '0123456789':
            sf = sf[:1]
        return int(sf)

    def _sf_to_dr(self, sf):
        return "SF7BW125"

    def _make_stat_packet(self): #Paquete de Status
        now = datetime.datetime.now()
        STAT_PK["stat"]["time"] = "%d-%02d-%02d %02d:%02d:%02d GMT" % (now.year, now.month, now.day, now.hour, now.minute, now.second)
        STAT_PK["stat"]["rxnb"] = self.rxnb
        STAT_PK["stat"]["rxok"] = self.rxok
        STAT_PK["stat"]["rxfw"] = self.rxfw
        STAT_PK["stat"]["dwnb"] = self.dwnb
        STAT_PK["stat"]["txnb"] = self.txnb
        print("Make Status Packet")
        return json.dumps(STAT_PK)

    def _make_node_packet(self, rx_data, rx_time, tmst, sf, rssi, snr):
        RX_PK["rxpk"][0]["time"] = "%d-%02d-%02dT%02d:%02d:%02d.%dZ" % (rx_time.year, rx_time.month, rx_time.day, rx_time.hour, rx_time.minute, rx_time.second, rx_time.microsecond)
        RX_PK["rxpk"][0]["tmst"] = tmst
        RX_PK["rxpk"][0]["datr"] = self._sf_to_dr(sf)
        RX_PK["rxpk"][0]["rssi"] = rssi
        RX_PK["rxpk"][0]["lsnr"] = float(snr)
        RX_PK["rxpk"][0]["data"] = binascii.b2a_base64(rx_data)[:-1]
        RX_PK["rxpk"][0]["size"] = len(rx_data)
        return json.dumps(RX_PK)

    def LoRaPayloadEncrypt(self, payload_hex, frameCount, AppSKey, dev_addr, direction=UP_LINK):
        '''
        LoraMac decrypt

        Which is actually encrypting a predefined 16-byte block (ref LoraWAN
        specification 4.3.3.1) and XORing that with each block of data.

        payload_hex: hex-encoded payload (FRMPayload)
        sequence_counter: integer, sequence counter (FCntUp)
        key: 16-byte hex-encoded AES key. (i.e. AABBCCDDEEFFAABBCCDDEEFFAABBCCDD)
        dev_addr: 4-byte hex-encoded DevAddr (i.e. AABBCCDD)
        direction: 0 for uplink packets, 1 for downlink packets

        returns an array of byte values.

        This method is based on `void LoRaMacPayloadEncrypt()` in
        https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/LoRaMacCrypto.c#L108
        '''
        AppSKey = unhexlify(AppSKey)
        dev_addr = unhexlify(dev_addr)
        buffer = bytearray(unhexlify(payload_hex))
        size = len(buffer)

        bufferIndex = 0
        # block counter
        ctr = 1

        # output buffer, initialize to input buffer size.
        encBuffer = [0x00] * size

        cipher = Cipher(algorithms.AES(AppSKey), modes.ECB(), backend=default_backend())

        def aes_encrypt_block(aBlock):
            '''
            AES encrypt a block.
            aes.encrypt expects a string, so we convert the input to string and
            the return value to bytes again.
            '''
            encryptor = cipher.encryptor()

            return bytearray(
                encryptor.update(self.to_bytes(aBlock)) + encryptor.finalize()
            )

        # For the exact definition of this block refer to
        # 'chapter 4.3.3.1 Encryption in LoRaWAN' in the LoRaWAN specification
        aBlock = bytearray([
            0x01,                             # 0 always 0x01
            0x00,                             # 1 always 0x00
            0x00,                             # 2 always 0x00
            0x00,                             # 3 always 0x00
            0x00,                             # 4 always 0x00
            direction,                        # 5 dir, 0 for uplink, 1 for downlink
            dev_addr[3],                      # 6 devaddr, lsb
            dev_addr[2],                      # 7 devaddr
            dev_addr[1],                      # 8 devaddr
            dev_addr[0],                      # 9 devaddr, msb
            frameCount & 0xff,          # 10 sequence counter (FCntUp) lsb
            (frameCount >> 8) & 0xff,   # 11 sequence counter
            (frameCount >> 16) & 0xff,  # 12 sequence counter
            (frameCount >> 24) & 0xff,  # 13 sequence counter (FCntUp) msb
            0x00,                             # 14 always 0x01
            0x00                              # 15 block counter
        ])

        # complete blocks
        while size >= 16:
            aBlock[15] = ctr & 0xFF
            ctr += 1
            sBlock = aes_encrypt_block(aBlock)
            for i in range(16):
                encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i]

            size -= 16
            bufferIndex += 16

        # partial blocks
        if size > 0:
            aBlock[15] = ctr & 0xFF
            sBlock = aes_encrypt_block(aBlock)
            for i in range(size):
                encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i]

        return encBuffer

    def _push_data(self, data):
        token = os.urandom(2)
        packet = PROTOCOL_VERSION + token + PUSH_DATA + binascii.unhexlify(self.id) + (data)
        print(packet)
        with self.udp_lock:
            try:
                self.sock.sendto(packet, self.server_ip)
                print("Push Data")
            except Exception:
                print("PUSH exception")


    def _pull_data(self):
        token = os.urandom(2)
        packet = PROTOCOL_VERSION + token + PULL_DATA + binascii.unhexlify(self.id)
        with self.udp_lock:
            try:
                self.sock.sendto(packet, self.server_ip)
                print("Send Pull data")
            except Exception:
                print("PULL exception")

    def _ack_pull_rsp(self, token, error):
        TX_ACK_PK["txpk_ack"]["error"] = error
        resp = json.dumps(TX_ACK_PK)
        packet = PROTOCOL_VERSION + token + PULL_ACK + binascii.unhexlify(self.id) + resp
        with self.udp_lock:
            try:
                self.sock.sendto(packet, self.server_ip)
                print("ack")
            except Exception:
                print("PULL RSP ACK exception")

    def _lora_cb(self, lora):
        events = 1#lora.events()
        if events & 1: #LoRa.RX_PACKET_EVENT
            self.rxnb += 1
            self.rxok += 1
            rx_data = "hola" #self.lora_sock.recv(256)
            # stats=(timestamp, rssi, snr, sf)
            #stats = lora.stats()
            #marca de tiempo del paquete
            stats.timestamp = int(time.time())
            self._push_data(self._make_node_packet(rx_data, datetime.datetime.now(), stats.timestamp, stats.sf, stats.rssi, stats.snr))
            self.rxfw += 1
            print("LoRa.RX_PACKET_EVENT")
        if events & 0: #LoRa.TX_PACKET_EVENT
            self.txnb += 1
            lora.init(mode=LoRa.LORA, frequency=self.frequency, bandwidth=LoRa.BW_125KHZ,
                      sf=self.sf, preamble=8, coding_rate=LoRa.CODING_4_5, tx_iq=True)
            print("LoRa.TX_PACKET_EVENT")

    def _send_down_link(self, data, tmst, datarate, frequency):
        self.lora.init(mode=LoRa.LORA, frequency=frequency, bandwidth=LoRa.BW_125KHZ,
                       sf=self._dr_to_sf(datarate), preamble=8, coding_rate=LoRa.CODING_4_5,
                       tx_iq=True)
        while time.ticks_us() < tmst:
            pass
        self.lora_sock.send(data)

    def _udp_thread(self):
        while True:
            try:
                data, src = self.sock.recvfrom(1024)
                _token = data[1:3]
                _type = data[3]
                if _type == PUSH_ACK:
                    print("Push ack")
                elif _type == PULL_ACK:
                    print("Pull ack")
                elif _type == PULL_RESP:
                    self.dwnb += 1
                    ack_error = TX_ERR_NONE
                    tx_pk = json.loads(data[4:])
                    tmst = tx_pk["txpk"]["tmst"]
                    t_us = tmst - time.ticks_us() - 5000
                    if t_us < 0:
                        t_us += 0xFFFFFFFF
                    if t_us < 20000000:
                        self.uplink_alarm = Timer.Alarm(handler=lambda x: self._send_down_link(binascii.a2b_base64(tx_pk["txpk"]["data"]),
                                                                                               tx_pk["txpk"]["tmst"] - 10, tx_pk["txpk"]["datr"],
                                                                                               int(tx_pk["txpk"]["freq"] * 1000000)), us=t_us)
                        print("Downlink")
                    else:
                        ack_error = TX_ERR_TOO_LATE
                        print("Downlink timestamp error!, t_us:", t_us)
                    self._ack_pull_rsp(_token, ack_error)
                    print("Pull rsp")
            except socket.timeout:
                pass
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    pass
                else:
                    print("UDP recv OSError Exception")
            except Exception:
                print("UDP recv Exception")
            # Wait before trying to receive again
            time.sleep(0.025)
