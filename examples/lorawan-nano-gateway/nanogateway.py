""" LoPy Nano Gateway class """

#from network import WLAN
#from network import LoRa
#from machine import Timer
import os
import binascii
#import machine
import json
import time
import errno
import _thread
import socket
import time
import datetime
from threading import Timer

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

frameCount = 1

DevAddr = [ 0x02, 0x02, 0x04, 0x20 ];	#Note: byte swapping done later

AppSKey = [ 0x02, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x54, 0x68, 0x69, 0x6E, 0x67, 0x73, 0x34, 0x55 ];


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
        # Change WiFi to STA mode and connect
        #self.wlan = WLAN(mode=WLAN.STA)
        #self._connect_to_wifi()
        self._make_node_data()

        # Get a time Sync
        #self.rtc = datetime.datetime.now()
        #self.rtc.ntp_sync(self.ntp, update_period=self.ntp_period)

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

#Based in https://github.com/things4u/ESP-1ch-Gateway-v4.0/blob/master/ESP-sc-gway/_sensor.ino#L163
    def _make_node_data(self):
        global frameCount
        message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        mlength = 0
        tmst = 0

        # In the next few bytes the fake LoRa message must be put
        # PHYPayload = MHDR | MACPAYLOAD | MIC
        # MHDR, 1 byte (part of MACPayload)
        message[0] = '\x40'								# 0x40 == unconfirmed up message

        # MACPayload:  FHDR + FPort + FRMPayload
        # FHDR consists of 4 bytes addr, 1byte Fctrl, 2bye FCnt, 0-15 byte FOpts
        #	We support ABP addresses only for Gateways
        message[1] = DevAddr[3]							# Last byte[3] of address
        message[2] = DevAddr[2]
        message[3] = DevAddr[1]
        message[4] = DevAddr[0]							# First byte[0] of Dev_Addr
        message[5] = 0x00							    # FCtrl is normally 0
        message[6] = frameCount % 0x100					# LSB
        message[7] = frameCount / 0x100					# MSB


        # FPort, either 0 or 1 bytes. Must be != 0 for non MAC messages such as user payload
        message[8] = 0x01									# Port must not be 0
        mlength = 9

        print(message)
        # FRMPayload; Payload will be AES128 encoded using AppSKey
        # See LoRa spec para 4.3.2
        # You can add any byte string below based on you personal
        # choice of sensors etc.

        # Payload bytes in this example are encoded in the LoRaCode(c) format
        #PayLength = LoRaSensors((uint8_t *)(message+mlength));

        # we have to include the AES functions at this stage in order to generate LoRa Payload.
        #encodePacket((uint8_t *)(message+mlength), PayLength, frameCount, 0);

        #mlength += PayLength								# length inclusive sensor data
        mlength += 4										# LMIC Not Used but we have to add MIC bytes to PHYPayload

        frameCount += 1

        print("sensorPacket")
        #buff_index = buildPacket(tmst, buff_up, message, mlength, true);
        return(buff_index);

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


    def encodePacket(Data, DataLength, FrameCount, Direction):

            #i, j
    	    #Block_A[16]
    	    #bLen=16;						# Block length is 16 except for last block in message
    	    restLength = DataLength % 16	# We work in blocks of 16 bytes, this is the rest
    	    numBlocks  = DataLength / 16	# Number of whole blocks to encrypt
            if restLength > 0:
                numBlocks += 1			# And add block for the rest if any
            for i in numBlocks:
                Block_A[0] = 0x01;
                Block_A[1] = 0x00;
                Block_A[2] = 0x00;
                Block_A[3] = 0x00;
                Block_A[4] = 0x00;

                Block_A[5] = Direction;				# 0 is uplink

                Block_A[6] = DevAddr[3];			# Only works for and with ABP
                Block_A[7] = DevAddr[2];
                Block_A[8] = DevAddr[1];
                Block_A[9] = DevAddr[0];

                Block_A[10] = (FrameCount & 0x00FF);
                Block_A[11] = ((FrameCount >> 8) & 0x00FF);
                Block_A[12] = 0x00; 				# Frame counter upper Bytes
                Block_A[13] = 0x00;					# These are not used so are 0

                Block_A[14] = 0x00;
                Block_A[15] = i;

                # Encrypt and calculate the S
                AES_Encrypt(Block_A, AppSKey);

                # Last block? set bLen to rest
                if (i == numBlocks) and (restLength>0):
                    bLen = restLength
                for j in bLen:
                    #*Data = *Data ^ Block_A[j]
                    Data += 1


    	        #return(numBlocks*16);			# Do we really want to return all 16 bytes in lastblock
    	        return(DataLength);				# or only 16*(numBlocks-1)+bLen;





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
