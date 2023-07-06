# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
import datetime
import time

import threading
try:
    import queue
except ImportError:
    import Queue as queue
from typing import Any
from enoceanjob.protocol.packet import Packet, UTETeachInPacket, MSGChainer, ChainedMSG, ResponsePacket, RadioPacket
from enoceanjob.protocol.constants import PACKET, PARSE_RESULT, RETURN_CODE


class Communicator(threading.Thread):
    '''
    Communicator base-class for enoceanjob.
    Not to be used directly, only serves as base class for SerialCommunicator etc.
    '''
    logger = logging.getLogger('enoceanjob.communicators.Communicator')

    def __init__(self, callback=None, teach_in=True):
        super(Communicator, self).__init__()
        # Create an event to stop the thread
        self._stop_flag = threading.Event()
        # Input buffer
        self._buffer = []
        # Setup packet queues
        self.transmit = queue.Queue()
        self.receive = queue.Queue()
        # Set the callback method
        self.__callback = callback
        # Internal variable for the Base ID of the module.
        self._base_id = None
        self._dgl_info: dict[str, Any] = {}
        self._dgl_info['app_version'] = "unknown"
        self._dgl_info['api_version'] = "unknown"
        self._dgl_info['chip_id'] = [0x00] * 4
        self._dgl_info['app_descr'] = "unknown"
        self._dgl_info['base_id'] = [0xFF] * 4
        # Should new messages be learned automatically? Defaults to True.
        # TODO: Not sure if we should use CO_WR_LEARNMODE??
        self.teach_in = teach_in
        self.chained = MSGChainer()

    def _get_from_send_queue(self):
        ''' Get message from send queue, if one exists '''
        try:
            packet = self.transmit.get(block=False)
            self.logger.info('Sending packet')
            self.logger.debug(packet)
            return packet
        except queue.Empty:
            pass
        return None

    def send(self, packet):
        
        if not isinstance(packet, Packet):
            self.logger.error('Object to send must be an instance of Packet')
            return False

        self.transmit.put(packet)
        return True
    
    def send_list(self, packet_list):
        if not isinstance(packet_list, list):
            self.logger.error('Object to send must be a list of Packet')
            return False
        
        for pckt in packet_list:
            if not isinstance(pckt, Packet):
                self.logger.warn('Object in the list is not a Packet')
                continue
            self.transmit.put(pckt)
            time.sleep(0.05)
        
        return True
    
    def send_secure_teach_in(self):
        pass

    def send_encrypt(self):
        pass

    def stop(self):
        self._stop_flag.set()

    def parse(self):
        ''' Parses messages and puts them to receive queue '''
        # Loop while we get new messages
        while True:
            status, self._buffer, packet = Packet.parse_msg(self._buffer)
            # If message is incomplete -> break the loop
            if status == PARSE_RESULT.INCOMPLETE:
                return status

            # If message is OK, add it to receive queue or send to the callback method
            if status == PARSE_RESULT.OK and packet:
                packet.received = datetime.datetime.now()

                #If received packet is UTETeachIn create response and send it (using base_id)
                if isinstance(packet, UTETeachInPacket) and self.teach_in:
                    response_packet = packet.create_response_packet(self.base_id)
                    self.logger.info('Sending response to UTE teach-in.')
                    self.send(response_packet)

                #If no callback defined for comunicator instanciation put packet in the receive queue
                if self.__callback is None:
                    self.receive.put(packet)
                #Else pass the packet to the callback function
                else:
                    #If packet is a response from the module put it in the queue (necessary for dongle info to work with callback)
                    if isinstance(packet, ResponsePacket):
                        self.receive.put(packet)
                    self.__callback(packet)
                
                self.logger.debug(packet)

                # Manage received chained messages (compile messsages in a virtual packet and put it in the queue or pass to callback)
                if isinstance(packet, ChainedMSG):
                    virtual = self.chained.parse_CDM(packet)
                    if virtual:
                        if self.__callback is None:
                            self.receive.put(virtual)
                        else:
                            self.__callback(virtual)
                        self.logger.debug(virtual)

    def get_dongle_info(self) -> dict[str, Any]:
        ''' Fetches transmitter information using CO_RD_VERSION and CO_RD_IDBASE'''
        # Send COMMON_COMMAND 0x03, CO_RD_VERSION request to the module
        self.send(Packet(PACKET.COMMON_COMMAND, data=[0x03]))

        # Loop over 10 times, to make sure we catch the response.
        # Thanks to timeout, shouldn't take more than a second.
        # Unfortunately, all other messages received during this time are ignored.
        for i in range(0, 10):
            try:
                packet = self.receive.get(block=True, timeout=0.1)
                # We're only interested in responses to the request in question.
                if packet.packet_type == PACKET.RESPONSE and packet.response == RETURN_CODE.OK and len(packet.response_data) == 32:
                    # Dongle info is set in the response data.
                    self._dgl_info['app_version'] = '.'.join(str(v) for v in packet.response_data[0:4])
                    self._dgl_info['api_version'] = '.'.join(str(v) for v in packet.response_data[4:8])
                    self._dgl_info['chip_id'] = packet.response_data[8:12]
                    self._dgl_info['app_descr'] = ''.join(bytearray(packet.response_data[16:32]).decode('utf-8'))
                    break
                # Put other packets back to the Queue.
                self.receive.put(packet)
            except queue.Empty:
                continue
        
        # Send COMMON_COMMAND 0x08, CO_RD_IDBASE request to the module
        self.send(Packet(PACKET.COMMON_COMMAND, data=[0x08]))

        # Loop over 10 times, to make sure we catch the response.
        # Thanks to timeout, shouldn't take more than a second.
        # Unfortunately, all other messages received during this time are ignored.
        for i in range(0, 10):
            try:
                packet = self.receive.get(block=True, timeout=0.1)
                # We're only interested in responses to the request in question.
                if packet.packet_type == PACKET.RESPONSE and packet.response == RETURN_CODE.OK and len(packet.response_data) == 4:
                    # Base ID is set in the response data.
                    self._dgl_info['base_id'] = packet.response_data
                    break
                # Put other packets back to the Queue.
                self.receive.put(packet)
            except queue.Empty:
                continue

        return self._dgl_info

    def set_transparent_mode(self, TM: int=0x01) -> bool:
        '''Function: This command enables/disables transparent mode. In general it disables chaining, 
           encryption and remote management functions and will forward all received telegrams into 
           the ESP3 interface without any processing applied.'''
        response: bool = False

        # Send COMMON_COMMAND 0x08, CO_WR_TRANSPARENT_MODE request to the module
        self.send(Packet(PACKET.COMMON_COMMAND, data=[0x3E, TM]))

        # Loop over 10 times, to make sure we catch the response.
        # Thanks to timeout, shouldn't take more than a second.
        # Unfortunately, all other messages received during this time are ignored.
        for i in range(0, 10):
            try:
                packet = self.receive.get(block=True, timeout=0.1)
                # We're only interested in responses to the request in question.
                if packet.packet_type == PACKET.RESPONSE and packet.response == RETURN_CODE.OK:
                    response = True
                    break
                # Put other packets back to the Queue.
                self.receive.put(packet)
            except queue.Empty:
                continue
        '''TCM310 USB modules responds NOT_SUPPORTED but transparent mode seems to be active'''
        return response
    
    def send_request(self,command: RadioPacket) -> RadioPacket | bool:
        """Send a request to a device and get response telegram
            Return false if no response"""

        response = False

        self.send(command)

        for i in range(0, 10):
            try:
                packet = self.receive.get(block=True, timeout=0.1)
                # We're only interested in responses to the request in question.
                if packet.packet_type == PACKET.RADIO_ERP1 and packet.sender_hex == command.destination_hex:
                    print("sender: ", packet.sender_hex)
                    response = packet
                    break
                    #return packet
                # Put other packets back to the Queue.
                #self.receive.put(packet)
            except queue.Empty:
                continue

        return response

    @property
    def base_id(self):
        ''' Dongle base id, return base ID of the dongle'''
        return self._dgl_info['base_id']

    @base_id.setter
    def base_id(self, base_id):
        ''' Sets the Base ID manually, only for testing purposes. '''
        self._base_id = base_id

    @property
    def eurid(self):
        ''' Dongle CHIP ID (EnOcean Unique Radio Identifier – EURID) '''
        return self._dgl_info['chip_id']

    @property
    def app_version(self):
        '''Transmitter application version'''
        return self._dgl_info['app_version']
    
    @property
    def api_version(self):
        '''Transmitter API version'''
        return self._dgl_info['api_version']
    
    @property
    def app_description(self):
        '''Transmitter application description'''
        return self._dgl_info['app_descr']
    
