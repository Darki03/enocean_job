#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Final test with SEC_TYI and first commands 
from enoceanjob.protocol.packet import RadioPacket, ChainedMSG, Packet, MSGChainer, SECTeachInPacket
from enoceanjob.utils import *
from enoceanjob.communicators.serialcommunicator import SerialCommunicator
from enoceanjob.protocol.constants import PACKET, RORG, DECRYPT_RESULT
from enoceanjob.consolelogger import init_logging
import sys
import traceback
import time
import keyboard
import msvcrt

try:
    import queue
except ImportError:
    import Queue as queue

#Gateway Acknowledge frame
def create_GW_ack_packet(Key, RLC, SLF, destination):
     decrypted = RadioPacket.create(rorg=RORG.VLD, rorg_func=0x33, rorg_type=0x00, destination = destination, MID=0, REQ=15)
     return decrypted.encrypt(Key,RLC,SLF)

def create_GW_SnF(Key, RLC, SLF, destination):
     decrypted = RadioPacket.create(rorg=RORG.VLD, rorg_func=0x33, rorg_type=0x00, destination = destination, MID=0, REQ=8)
     return decrypted.encrypt(Key,RLC,SLF)

def create_GW_SParam(Key, RLC, SLF, destination):
     decrypted = RadioPacket.create(rorg=RORG.VLD, rorg_func=0x33, rorg_type=0x00, destination = destination, MID=1, TNS=1, DCS=5, WOS=1, PIS=1)
     return decrypted.encrypt(Key,RLC,SLF)

def create_GW_program(Key, RLC, SLF, destination, SP=9):
     decrypted = RadioPacket.create(rorg=RORG.VLD, rorg_func=0x33, rorg_type=0x00, destination = destination, MID=2, TSP=SP)
     encrypted = decrypted.encrypt(Key,RLC,SLF)
     if len(encrypted.data) > 15:
          return ChainedMSG.create_CDM(encrypted,CDM_RORG=RORG.CDM)
     else:
          return encrypted
     
def add_one_to_RLC(RLC):
     if RLC == []:
          return RLC
     int_RLC_in = combine_hex(RLC)
     int_RLC_in += 1
     return list(int_RLC_in.to_bytes(len(RLC), 'big'))

# dest = [0x05,0x03,0x06,0x1B]
# dest = [0x05,0x16,0xF0,0xE3]
dest = [0x05,0x16,0xE2,0xE1]

Key = list(bytearray.fromhex("40C9A1DD95D829F842FE46E10E51828E"))

SECTI = SECTeachInPacket.create_SECTI_chain(SLF=0x8B, Key=Key,destination=dest)



# Dat_send = enocean.utils.from_hex_string("20:00:00:00:15:E0")
# Raw1664=RadioPacket.create_raw(rorg=RORG.VLD, Raw_Data=Dat_send, destination = [0x05, 0x03, 0x06, 0x1B])

# Raw1664=RadioPacket.create(rorg=RORG.VLD, rorg_func=0x33, rorg_type=0x00, destination = dest,mid=2, MID=2, TSP=17)
# print(enocean.utils.to_hex_string(Raw1664.build()))
# print(len(Raw1664.data))
# print(type(Raw1664))
# print(enocean.utils.to_hex_string(SECTI[1].build()))s
# print(enocean.utils.to_hex_string(SECTI[1].SLF))
# print(enocean.utils.to_hex_string(SECTI[1].RLC))
# print(enocean.utils.to_hex_string(SECTI[1].KEY))

# Raw1664 = Raw1664.encrypt(bytearray(SECTI[1].KEY),SECTI[1].RLC,SECTI[1].SLF)
# Raw1664 = create_GW_program(bytearray(SECTI[1].KEY),[0x00, 0x00, 0x24],SECTI[1].SLF, dest, SP=17)
# print(enocean.utils.to_hex_string(Raw1664.build()))
# print(len(Raw1664.data)-5)

# sec_command = ChainedMSG.create_CDM(Raw1664,CDM_RORG=RORG.SEC_CDM)

# for packet in Raw1664:
#     print(enocean.utils.to_hex_string(packet.build()))


# Raw1664 = create_GW_ack_packet(bytearray(SECTI[1].KEY),SECTI[1].RLC,SECTI[1].SLF, dest)
# print(enocean.utils.to_hex_string(Raw1664.build()))


# for packet in SECTI[0]:
#     print(enocean.utils.to_hex_string(packet.build()))
#     print(packet.IDX,":", packet.CNT,":",packet.PSK,":",packet.TYPE,":",packet.INFO)





#Initialize RLC
RLC_GW = SECTI[1].RLC
RLC_SENS = SECTI[1].RLC
init_logging()
communicator = SerialCommunicator(port=u'COM10')
communicator.start()
communicator.get_dongle_info()
print('The Base ID of your module is %s.' % to_hex_string(communicator.base_id))
print('The EURID of your module is %s.' % to_hex_string(communicator.eurid))
print(communicator.app_description)
print(communicator.app_version)
print(communicator.api_version)
print(communicator.set_transparent_mode(0x01))

#communicator.send(Packet(PACKET.COMMON_COMMAND, data=[0x3E, 0x01]))
time.sleep(1)
# communicator.send_list(SECTI[0])
# time.sleep(1)
# communicator.send_list(sec_command)

# for p in SECTI:
#     communicator.send(p)
#     print(enocean.utils.to_hex_string(p.build()))


while communicator.is_alive():
            try:
                if keyboard.is_pressed('space'):
                    print("MID1")
                    communicator.send(create_GW_SParam(bytearray(SECTI[1].KEY), RLC_GW, SECTI[1].SLF, dest))
                    # RLC_GW = add_one_to_RLC(RLC_GW)
                if keyboard.is_pressed('s'):
                    print("MID0")
                    # communicator.send(create_GW_SnF(bytearray(SECTI[1].KEY), RLC_GW, SECTI[1].SLF, dest))
                    packet = communicator.send_request(create_GW_SnF(bytearray(SECTI[1].KEY), RLC_GW, SECTI[1].SLF, dest))
                    print("Answer is:", packet)
                    RLC_GW = add_one_to_RLC(RLC_GW)
                if keyboard.is_pressed('t'):
                    TSP = input("T:")
                    communicator.send_list(create_GW_program(bytearray(SECTI[1].KEY), RLC_GW, SECTI[1].SLF, dest,SP=int(TSP)))
                    # RLC_GW = add_one_to_RLC(RLC_GW)es
                if keyboard.is_pressed('e'):
                     RLC_GW = SECTI[1].RLC
                     RLC_SENS = SECTI[1].RLC
                     communicator.send_list(SECTI[0])
                packet = communicator.receive.get(block=True, timeout=0.1)
                # We're only interested in responses to the request in question.
                # if packet.packet_type == PACKET.RESPONSE:
                #     print(enocean.utils.to_hex_string(packet.build()))
                # Put other packets back to the Queue.
                if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.SEC_ENCAPS and packet.sender == dest:
                    #print("test:", RLC_SENS)
                    Decode_packet = packet.decrypt(bytearray(SECTI[1].KEY), RLC_SENS, SECTI[1].SLF)
                    # print(Decode_packet[1], Decode_packet[2])
                    RLC_SENS = add_one_to_RLC(Decode_packet[2])
                    if Decode_packet[1] == DECRYPT_RESULT.OK:
                        Decode_packet[0].select_eep(0x33, 0x00)
                        Decode_packet[0].parse_eep()
                        if (Decode_packet[0].parsed['MID']['raw_value'] == 8 and (Decode_packet[0].parsed['REQ']['raw_value'] == 0 or Decode_packet[0].parsed['REQ']['raw_value'] == 4)) or Decode_packet[0].parsed['MID']['raw_value'] > 8:
                             communicator.send(create_GW_ack_packet(bytearray(SECTI[1].KEY), RLC_GW, SECTI[1].SLF, dest))
                            #  RLC_GW = add_one_to_RLC(RLC_GW)
                        for k in Decode_packet[0].parsed:
                            print('%s: %s' % (k, Decode_packet[0].parsed[k]))
                if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.SEC_ENCAPS and packet.destination == dest:
                    Decode_packet = packet.decrypt(bytearray(SECTI[1].KEY), RLC_GW, SECTI[1].SLF)
                    RLC_GW = add_one_to_RLC(RLC_GW)
                    # print(Decode_packet[1], Decode_packet[2])
                    if Decode_packet[1] == DECRYPT_RESULT.OK: 
                        #eRLC_GW = Decode_packet[2]
                        Decode_packet[0].select_eep(0x33, 0x00)
                        Decode_packet[0].parse_eep()
                        for k in Decode_packet[0].parsed:
                            print('%s: %s' % (k, Decode_packet[0].parsed[k])) 
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                break
            except Exception:
                traceback.print_exc(file=sys.stdout)
                break


if communicator.is_alive():
    communicator.stop()

