# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
from collections import OrderedDict

import math
import enoceanjob.utils
from enoceanjob.protocol import crc8
from enoceanjob.protocol import security
from Crypto.Random import get_random_bytes
from enoceanjob.protocol.eep import EEP
from enoceanjob.protocol.constants import PACKET, RORG, PARSE_RESULT, DECRYPT_RESULT, DB0, DB2, DB3, DB4, DB6, SLF_INFO


class Packet(object):
    '''
    Base class for Packet.
    Mainly used for for packet generation and
    Packet.parse_msg(buf) for parsing message.
    parse_msg() returns subclass, if one is defined for the data type.
    '''
    eep = EEP()
    logger = logging.getLogger('enoceanjob.protocol.packet')

    def __init__(self, packet_type, data=None, optional=None):
        self.packet_type = packet_type
        self.rorg = RORG.UNDEFINED
        self.rorg_func = None
        self.rorg_type = None
        self.rorg_manufacturer = None

        self.received = None

        if not isinstance(data, list) or data is None:
            self.logger.warning('Replacing Packet.data with default value.')
            self.data = []
        else:
            self.data = data

        if not isinstance(optional, list) or optional is None:
            self.logger.warning('Replacing Packet.optional with default value.')
            self.optional = []
        else:
            self.optional = optional

        self.status = 0
        self.parsed = OrderedDict({})
        self.repeater_count = 0
        self._profile = None

        self.parse()

    def __str__(self):
        return '0x%02X %s %s %s' % (self.packet_type, [hex(o) for o in self.data], [hex(o) for o in self.optional], self.parsed)

    def __unicode__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.packet_type == other.packet_type and self.rorg == other.rorg and self.data == other.data and self.optional == other.optional

    @property
    def _bit_data(self):
        # First and last 5 bits are always defined, so the data we're modifying is between them...
        # TODO: This is valid for the packets we're currently manipulating.
        # Needs the redefinition of Packet.data -> Packet.message.
        # Packet.data would then only have the actual, documented data-bytes. Packet.message would contain the whole message.
        # See discussion in issue #14
        return enoceanjob.utils.to_bitarray(self.data[1:len(self.data) - 5], (len(self.data) - 6) * 8)

    @_bit_data.setter
    def _bit_data(self, value):
        # The same as getting the data, first and last 5 bits are ommitted, as they are defined...
        for byte in range(len(self.data) - 6):
            self.data[byte+1] = enoceanjob.utils.from_bitarray(value[byte*8:(byte+1)*8])

    # # COMMENTED OUT, AS NOTHING TOUCHES _bit_optional FOR NOW.
    # # Thus, this is also untested.
    # @property
    # def _bit_optional(self):
    #     return enoceanjob.utils.to_bitarray(self.optional, 8 * len(self.optional))

    # @_bit_optional.setter
    # def _bit_optional(self, value):
    #     if self.rorg in [RORG.RPS, RORG.BS1]:
    #         self.data[1] = enoceanjob.utils.from_bitarray(value)
    #     if self.rorg == RORG.BS4:
    #         for byte in range(4):
    #             self.data[byte+1] = enoceanjob.utils.from_bitarray(value[byte*8:(byte+1)*8])

    @property
    def _bit_status(self):
        return enoceanjob.utils.to_bitarray(self.status)

    @_bit_status.setter
    def _bit_status(self, value):
        self.status = enoceanjob.utils.from_bitarray(value)

    @staticmethod
    def parse_msg(buf):
        '''
        Parses message from buffer.
        returns:
            - PARSE_RESULT
            - remaining buffer
            - Packet -object (if message was valid, else None)
        '''
        # If the buffer doesn't contain 0x55 (start char)
        # the message isn't needed -> ignore
        if 0x55 not in buf:
            return PARSE_RESULT.INCOMPLETE, [], None

        # Valid buffer starts from 0x55
        # Convert to list, as index -method isn't defined for bytearray
        buf = [ord(x) if not isinstance(x, int) else x for x in buf[list(buf).index(0x55):]]
        try:
            data_len = (buf[1] << 8) | buf[2]
            opt_len = buf[3]
        except IndexError:
            # If the fields don't exist, message is incomplete
            return PARSE_RESULT.INCOMPLETE, buf, None

        # Header: 6 bytes, data, optional data and data checksum
        msg_len = 6 + data_len + opt_len + 1
        if len(buf) < msg_len:
            # If buffer isn't long enough, the message is incomplete
            return PARSE_RESULT.INCOMPLETE, buf, None

        msg = buf[0:msg_len]
        buf = buf[msg_len:]

        packet_type = msg[4]
        data = msg[6:6 + data_len]
        opt_data = msg[6 + data_len:6 + data_len + opt_len]

        # Check CRCs for header and data
        if msg[5] != crc8.calc(msg[1:5]):
            # Fail if doesn't match message
            Packet.logger.error('Header CRC error!')
            # Return CRC_MISMATCH
            return PARSE_RESULT.CRC_MISMATCH, buf, None
        if msg[6 + data_len + opt_len] != crc8.calc(msg[6:6 + data_len + opt_len]):
            # Fail if doesn't match message
            Packet.logger.error('Data CRC error!')
            # Return CRC_MISMATCH
            return PARSE_RESULT.CRC_MISMATCH, buf, None

        # If we got this far, everything went ok (?)
        if packet_type == PACKET.RADIO_ERP1:
            # Need to handle UTE Teach-in here, as it's a separate packet type...
            if data[0] == RORG.UTE:
                packet = UTETeachInPacket(packet_type, data, opt_data)
            elif data[0] in [RORG.CDM, RORG.SEC_CDM]:
                packet = ChainedMSG(packet_type, data, opt_data)
            else:
                packet = RadioPacket(packet_type, data, opt_data)
        elif packet_type == PACKET.RESPONSE:
            packet = ResponsePacket(packet_type, data, opt_data)
        elif packet_type == PACKET.EVENT:
            packet = EventPacket(packet_type, data, opt_data)
        else:
            packet = Packet(packet_type, data, opt_data)

        return PARSE_RESULT.OK, buf, packet

    @staticmethod
    def create(packet_type, rorg, rorg_func, rorg_type, direction=None, command=None,
               destination=None,
               sender=None,
               learn=False, mid=None, **kwargs):
        '''
        Creates an packet ready for sending.
        Uses rorg, rorg_func and rorg_type to determine the values set based on EEP.
        Additional arguments (**kwargs) are used for setting the values.

        Currently only supports:
            - PACKET.RADIO_ERP1
            - RORGs RPS, BS1, BS4, VLD.

        TODO:
            - Require sender to be set? Would force the "correct" sender to be set.
            - Do we need to set telegram control bits?
              Might be useful for acting as a repeater?
        '''

        if packet_type != PACKET.RADIO_ERP1:
            # At least for now, only support PACKET.RADIO_ERP1.
            raise ValueError('Packet type not supported by this function.')

        if rorg not in [RORG.RPS, RORG.BS1, RORG.BS4, RORG.VLD]:
            # At least for now, only support these RORGS.
            raise ValueError('RORG not supported by this function.')

        if destination is None:
            Packet.logger.warning('Replacing destination with broadcast address.')
            destination = [0xFF, 0xFF, 0xFF, 0xFF]

        # TODO: Should use the correct Base ID as default.
        #       Might want to change the sender to be an offset from the actual address?
        if sender is None:
            Packet.logger.warning('Replacing sender with 0x00 address, BaseID will be used.')
            sender = [0x00, 0x00, 0x00, 0x00]

        if not isinstance(destination, list) or len(destination) != 4:
            raise ValueError('Destination must a list containing 4 (numeric) values.')

        if not isinstance(sender, list) or len(sender) != 4:
            raise ValueError('Sender must a list containing 4 (numeric) values.')

        packet = Packet(packet_type, data=[], optional=[])
        packet.rorg = rorg
        packet.data = [packet.rorg]
        # Select EEP at this point, so we know how many bits we're dealing with (for VLD).
        packet.select_eep(rorg_func, rorg_type, direction, command, mid)

        # Initialize data depending on the profile.
        if rorg in [RORG.RPS, RORG.BS1]:
            packet.data.extend([0])
        elif rorg == RORG.BS4:
            packet.data.extend([0, 0, 0, 0])
        else:
            data_size = 0
            for offs in packet._profile.find_all('bitsize'):
                if offs.find_parent('condition') is None:
                    data_size += int(offs.string)
            byte_size = int(data_size/8)    
            packet.data.extend([0] * byte_size)
        packet.data.extend(sender)
        packet.data.extend([0])
        # Always use sub-telegram 3, maximum dbm (as per spec, when sending),
        # and no security (security not supported as per EnOcean Serial Protocol).
        packet.optional = [3] + destination + [0xFF] + [0]

        if command and rorg == RORG.VLD:
            # Set CMD to command, if applicable.. Helps with VLD.
            kwargs['CMD'] = command

        packet.set_eep(kwargs)
        if rorg in [RORG.BS1, RORG.BS4] and not learn:
            if rorg == RORG.BS1:
                packet.data[1] |= (1 << 3)
            if rorg == RORG.BS4:
                packet.data[4] |= (1 << 3)
        packet.data[-1] = packet.status

        # Parse the built packet, so it corresponds to the received packages
        # For example, stuff like RadioPacket.learn should be set.
        packet = Packet.parse_msg(packet.build())[2]
        packet.rorg = rorg
        packet.parse_eep(rorg_func, rorg_type, direction, command)
        return packet

    def parse(self):
        ''' Parse data from Packet '''
        # Parse status from messages
        if self.rorg in [RORG.RPS, RORG.BS1, RORG.BS4]:
            self.status = self.data[-1]
        if self.rorg == RORG.VLD:
            self.status = self.optional[-1]

        if self.rorg in [RORG.RPS, RORG.BS1, RORG.BS4]:
            # These message types should have repeater count in the last for bits of status.
            self.repeater_count = enoceanjob.utils.from_bitarray(self._bit_status[4:])
        return self.parsed

    def select_eep(self, rorg_func, rorg_type, direction=None, command=None, mid=None):
        ''' Set EEP based on FUNC and TYPE '''
        # set EEP profile
        self.rorg_func = rorg_func
        self.rorg_type = rorg_type
        self._profile = self.eep.find_profile(self._bit_data, self._bit_status, self.rorg, rorg_func, rorg_type, direction, command, mid)
        return self._profile is not None

    def parse_eep(self, rorg_func=None, rorg_type=None, direction=None, command=None):
        ''' Parse EEP based on FUNC and TYPE '''
        # set EEP profile, if demanded
        if rorg_func is not None and rorg_type is not None:
            self.select_eep(rorg_func, rorg_type, direction, command)
        # parse data
        provides, values = self.eep.get_values(self._profile, self._bit_data, self._bit_status)
        self.parsed.update(values)
        return list(provides)

    def set_eep(self, data):
        ''' Update packet data based on EEP. Input data is a dictionary with keys corresponding to the EEP. '''
        self._bit_data, self._bit_status = self.eep.set_values(self._profile, self._bit_data, self._bit_status, data)

    def build(self):
        ''' Build Packet for sending to EnOcean controller '''
        data_length = len(self.data)
        ords = [0x55, (data_length >> 8) & 0xFF, data_length & 0xFF, len(self.optional), int(self.packet_type)]
        ords.append(crc8.calc(ords[1:5]))
        ords.extend(self.data)
        ords.extend(self.optional)
        ords.append(crc8.calc(ords[6:]))
        return ords

    @staticmethod
    def create_raw(packet_type, rorg, Raw_Data, direction=None, destination=None,
               sender=None, status=None):
        
        if packet_type != PACKET.RADIO_ERP1:
            # At least for now, only support PACKET.RADIO_ERP1.
            raise ValueError('Packet type not supported by this function.')
        
        if destination is None:
            Packet.logger.warning('Replacing destination with broadcast address.')
            destination = [0xFF, 0xFF, 0xFF, 0xFF]

        #Sends packet with EURID by default (sender address different from base ID start address)
        if sender is None:
            #Packet.logger.warning('Replacing sender with default address.')
            sender = [0x00, 0x00, 0x00, 0x00]

        if not isinstance(destination, list) or len(destination) != 4:
            raise ValueError('Destination must a list containing 4 (numeric) values.')

        if not isinstance(sender, list) or len(sender) != 4:
            raise ValueError('Sender must a list containing 4 (numeric) values.')
        
        if not isinstance(Raw_Data, list):
            raise ValueError('Raw_Data must be a list containing numeric values.')
        
        packet = Packet(packet_type, data=[], optional=[])
        packet.rorg = rorg
        packet.data = [packet.rorg]
        packet.data.extend(Raw_Data)
        packet.data.extend(sender)
        packet.data.extend([0])
        # Always use sub-telegram 3, maximum dbm (as per spec, when sending),
        # and no security (security not supported as per EnOcean Serial Protocol).
        if status is None:
            packet.optional = [3] + destination + [0xFF] + [0]
        else:
            packet.status = status
            packet.optional = [status] + destination + [0xFF] + [0]
        

        return packet
    
    def decrypt(self, Key, RLC = [], SLF_TI = 0x00, Window_Size = None):
        Out_packet = Packet(PACKET.RADIO_ERP1, data=[], optional=[])
        
        #Parse Sescure Level Format
        SLF_IN = security.SLF(SLF_TI)
        if SLF_IN.DATA_ENC!= 3:
            # At least for now, only support VAES
            return self, DECRYPT_RESULT.NOT_SUPPORTED
        
        #MAC_SIZE is SLC MAC_SIZE value + 2
        MAC_SIZE = SLF_IN.MAC_ALGO + 2
        RLC_SIZE = SLF_IN.RLC_ALGO + 1
        DATA_END = -5 - MAC_SIZE

        #Data fields extraction and RLC management
        if Window_Size is None:
            Window_Size = 0xFF

        if RLC != []:
            RLC_Start = RLC
            Window_Size = 0x80
        else:
            RLC_Start = [0x00] * RLC_SIZE

        if SLF_IN.RLC_TX == SLF_INFO.RLC_TX_YES:
            DATA_END = DATA_END - RLC_SIZE
            RLC_find = self.data[DATA_END:DATA_END+RLC_SIZE]
            CMAC = self.data[DATA_END+RLC_SIZE:-5]
        else:     
            CMAC = self.data[DATA_END:-5]
            Data_in = self.data[1:DATA_END]
            RLC_find = security.find_RLC(Key, self.data[:DATA_END], CMAC, RLC_Start, Window_Size)
            
        #RLC not retrieved, return input RLC and derypt result KO
        if RLC_find is None:
            return self, DECRYPT_RESULT.RLC_NOT_FIND, RLC
        
        Data_in = self.data[1:DATA_END]
        
        #Encrypt encrypted data = Decrypt data
        Data_in = security.VAES128(Key, Data_in, RLC_find)

        #Build decrypted packet
        Out_packet.rorg = Data_in[0]
        Out_packet.data.extend(Data_in)
        Out_packet.data.extend(self.data[-5:])
        Out_packet.optional.extend(self.optional)

        return Out_packet, DECRYPT_RESULT.OK, RLC_find
    
    def encrypt(self, Key, RLC = [], SLF_TI = 0x00):
        Out_packet = Packet(PACKET.RADIO_ERP1, data=[], optional=[])

        #Parse Sescure Level Format
        SLF_IN = security.SLF(SLF_TI)
        if SLF_IN.DATA_ENC!= 3:
            # At least for now, only support VAES
            self.logger.warn('SLF not supported')
            return self
        
        #MAC_SIZE is SLC MAC_SIZE value + 2
        MAC_SIZE = SLF_IN.MAC_ALGO + 2

        Data_in = self.data[:-5]

        #Encrypt data
        Data_in = security.VAES128(Key, Data_in, RLC)

        #Build output packet
        Out_packet.rorg = RORG.SEC_ENCAPS
        Out_packet.data.append(Out_packet.rorg)
        Out_packet.data.extend(Data_in)
        Out_packet.data.extend(security.CMAC_calc(Key, Out_packet.data, RLC, MAC_SIZE))
        Out_packet.data.extend(self.data[-5:])
        Out_packet.optional.extend(self.optional)

        return Out_packet
     

class RadioPacket(Packet):
    destination = [0xFF, 0xFF, 0xFF, 0xFF]
    dBm = 0
    sender = [0xFF, 0xFF, 0xFF, 0xFF]
    learn = True
    contains_eep = False

    def __str__(self):
        packet_str = super(RadioPacket, self).__str__()
        return '%s->%s (%d dBm): %s' % (self.sender_hex, self.destination_hex, self.dBm, packet_str)

    @staticmethod
    def create(rorg, rorg_func, rorg_type, direction=None, command=None,
               destination=None, sender=None, learn=False, mid=None, **kwargs):
        return Packet.create(PACKET.RADIO_ERP1, rorg, rorg_func, rorg_type, direction, command, destination, sender, learn, mid, **kwargs)
    
    @staticmethod
    def create_raw(rorg, Raw_Data, direction=None, destination=None,
               sender=None, status=None):
        return Packet.create_raw(PACKET.RADIO_ERP1, rorg, Raw_Data, direction, destination, sender, status)

    @property
    def sender_int(self):
        return enoceanjob.utils.combine_hex(self.sender)

    @property
    def sender_hex(self):
        return enoceanjob.utils.to_hex_string(self.sender)

    @property
    def destination_int(self):
        return enoceanjob.utils.combine_hex(self.destination)

    @property
    def destination_hex(self):
        return enoceanjob.utils.to_hex_string(self.destination)
    
    def encrypt(self, Key, RLC=[], SLF_TI=0):
        return super().encrypt(Key, RLC, SLF_TI)
    
    def decrypt(self, Key, RLC=[], SLF_TI=0, Window_Size=None):
        return super().decrypt(Key, RLC, SLF_TI, Window_Size)

    def parse(self):
        self.destination = self.optional[1:5]
        self.dBm = -self.optional[5]
        self.sender = self.data[-5:-1]
        # Default to learn == True, as some devices don't have a learn button
        self.learn = True

        self.rorg = self.data[0]

        # parse learn bit and FUNC/TYPE, if applicable
        if self.rorg == RORG.BS1:
            self.learn = not self._bit_data[DB0.BIT_3]
        if self.rorg == RORG.BS4:
            self.learn = not self._bit_data[DB0.BIT_3]
            if self.learn:
                self.contains_eep = self._bit_data[DB0.BIT_7]
                if self.contains_eep:
                    # Get rorg_func and rorg_type from an unidirectional learn packet
                    self.rorg_func = enoceanjob.utils.from_bitarray(self._bit_data[DB3.BIT_7:DB3.BIT_1])
                    self.rorg_type = enoceanjob.utils.from_bitarray(self._bit_data[DB3.BIT_1:DB2.BIT_2])
                    self.rorg_manufacturer = enoceanjob.utils.from_bitarray(self._bit_data[DB2.BIT_2:DB0.BIT_7])
                    self.logger.debug('learn received, EEP detected, RORG: 0x%02X, FUNC: 0x%02X, TYPE: 0x%02X, Manufacturer: 0x%02X' % (self.rorg, self.rorg_func, self.rorg_type, self.rorg_manufacturer))

        return super(RadioPacket, self).parse()


class SecurePacket(RadioPacket):
    slf = 0x8B
    RLC = []
    CMAC = []
    key = []

    def __str__(self):
        packet_str = super(RadioPacket, self).__str__()
        return '%s : %s->%s (%d dBm): %s' % ("SEC",self.sender_hex, self.destination_hex, self.dBm, packet_str)

    def parse(self):
        super(SecurePacket, self).parse()
        return self.parsed

#Packet subclass for chained messages management
#Parse id, index and data length
class ChainedMSG(RadioPacket):
    
    id = 0b01
    idx = 0b000000
    chain_len = 0x0000
    id_chain = 0b01

    def __str__(self):
        packet_str = super(ChainedMSG, self).__str__()
        return '%s %d-%d : %s->%s (%d dBm): %s' % ("CDM",self.id,self.idx,self.sender_hex, self.destination_hex, self.dBm, packet_str)

    @staticmethod
    def create_CDM(over_sized_packt, CDM_RORG=RORG.SEC_CDM):
        if len(over_sized_packt.data) <= 15 and over_sized_packt.destination != [0xFF,0xFF,0xFF,0xFF]:
            return over_sized_packt
        
        Start = 1
        chained_list = []

        data_len = len(over_sized_packt.data) - 6

        CHAIN_CTRL = (ChainedMSG.id_chain << 6) | 0x00
        header = [CDM_RORG] + [CHAIN_CTRL] + list(data_len.to_bytes(2, 'big'))

        if CDM_RORG == RORG.CDM:
            Start = 0

        data = over_sized_packt.data[Start:-5]
        
        data_i = header + data[:10-len(header)] + over_sized_packt.data[-5:]
        chained_list.append(ChainedMSG(PACKET.RADIO_ERP1,data=data_i, optional=over_sized_packt.optional))
        data = data[10-len(header):]
        
        N=math.ceil(len(data)/8)

        for i in range(N-1):
            CHAIN_CTRL = (ChainedMSG.id_chain << 6) | (i+1)
            header = [CDM_RORG] + [CHAIN_CTRL] + over_sized_packt.data[-5:]
            data_i = header + data[i*8:i*8+1]
            chained_list.append(ChainedMSG(PACKET.RADIO_ERP1,data=data_i, optional=over_sized_packt.optional))

        CHAIN_CTRL = (ChainedMSG.id_chain << 6) | N
        header = [CDM_RORG] + [CHAIN_CTRL]
        data_i = header + data[-(len(data)%8):] + over_sized_packt.data[-5:]
        chained_list.append(ChainedMSG(PACKET.RADIO_ERP1,data=data_i, optional=over_sized_packt.optional))

        ChainedMSG.id_chain += 1
        if ChainedMSG.id_chain == 4: ChainedMSG.id_chain = 1

        return chained_list

    def parse(self):
        super(ChainedMSG, self).parse()
        self.id = (self.data[1] & 0xC0) >> 6
        self.idx = self.data[1] & 0x3F
        if self.idx == 0:
            self.chain_len = (self.data[2] << 8) + self.data[3]
        return self.parsed

#Packet subclass for merged chained messages management
#VIRTUAL prefix
class VirtualPacket(RadioPacket):

    def __str__(self):
        packet_str = super(VirtualPacket, self).__str__()
        return '%s : %s->%s (%d dBm): %s' % ("VIRTUAL", self.sender_hex, self.destination_hex, self.dBm, packet_str)
    
    def parse(self):
        super(VirtualPacket, self).parse()
        return self.parsed

# Class for chained messages merging and creation
class MSGChainer(object):
    
    def __init__(self):
        self.chainid = None
        self.chainidx = None
        self.chained_data = []
        self.remaining_size = None

    def parse_CDM(self, packet):

        #If not a chained message packet do nothing
        if not isinstance(packet, ChainedMSG):
            return None
        
        #If the first chained packet is not the first of the chain (index > 0)
        # do nothing
        if self.chained_data == [] and packet.idx > 0:
            return None

        #Chain Encapsulation Size
        if packet.rorg == RORG.SEC_CDM: 
            CES = 9
        #if CDM 0x40 RORG of chained message is added to the data
        else: 
            CES = 10

        #If it is the first message of the chain
        if packet.idx == 0:
            self.chained_data.clear()
            self.chainid = packet.id
            self.chainidx = packet.idx
            self.remaining_size = packet.chain_len - (len(packet.data) - CES)
            if packet.rorg == RORG.SEC_CDM: self.chained_data.extend([RORG.SEC_ENCAPS._value_])
            self.chained_data.extend(packet.data[4:-5])
        #Rest of the chain if same chian id and idx + 1
        elif packet.id == self.chainid and packet.idx == (self.chainidx + 1):
            self.remaining_size -= (len(packet.data) - 7)
            self.chained_data.extend(packet.data[2:])

        if self.remaining_size == 0:
            return VirtualPacket(PACKET.RADIO_ERP1,data=self.chained_data, optional=packet.optional)
        
        return None
    
    def assemble_SEC_TI(self, sec_ti_chain):
        
        #If not a chained message packet do nothing
        if not isinstance(sec_ti_chain, SECTeachInPacket):
            return None
        
        #If the first chained packet is not the first of the chain (index > 0)
        # do nothing
        if self.chained_data == [] and sec_ti_chain.IDX > 0:
            return None      

        if sec_ti_chain.idx == 0:
            self.chained_data.clear()
            self.remaining_size = sec_ti_chain.CNT
            self.chained_data.extend(sec_ti_chain.data[1:-5])


        self.chained_data.extend(sec_ti_chain.data[2:-5])
        self.remaining_size -= 1

        if self.remaining_size == 0:
            return SECTeachInPacket(PACKET.RADIO_ERP1,data=self.chained_data,optional=sec_ti_chain.optional)
        
        return None

        

class UTETeachInPacket(RadioPacket):
    # Request types
    TEACH_IN = 0b00
    DELETE = 0b01
    NOT_SPECIFIC = 0b10

    # Response types
    NOT_ACCEPTED = [False, False]
    TEACHIN_ACCEPTED = [False, True]
    DELETE_ACCEPTED = [True, False]
    EEP_NOT_SUPPORTED = [True, True]

    unidirectional = False
    response_expected = False
    number_of_channels = 0xFF
    rorg_of_eep = RORG.UNDEFINED
    request_type = NOT_SPECIFIC
    channel = None

    contains_eep = True

    @property
    def bidirectional(self):
        return not self.unidirectional

    @property
    def teach_in(self):
        return self.request_type != self.DELETE

    @property
    def delete(self):
        return self.request_type == self.DELETE

    def parse(self):
        super(UTETeachInPacket, self).parse()
        self.unidirectional = not self._bit_data[DB6.BIT_7]
        self.response_expected = not self._bit_data[DB6.BIT_6]
        self.request_type = enoceanjob.utils.from_bitarray(self._bit_data[DB6.BIT_5:DB6.BIT_3])
        self.rorg_manufacturer = enoceanjob.utils.from_bitarray(self._bit_data[DB3.BIT_2:DB2.BIT_7] + self._bit_data[DB4.BIT_7:DB3.BIT_7])
        self.channel = self.data[2]
        self.rorg_type = self.data[5]
        self.rorg_func = self.data[6]
        self.rorg_of_eep = self.data[7]
        if self.teach_in:
            self.learn = True
        return self.parsed

    def create_response_packet(self, sender_id, response=TEACHIN_ACCEPTED):
        # Create data:
        # - Respond with same RORG (UTE Teach-in)
        # - Always use bidirectional communication, set response code, set command identifier.
        # - Databytes 5 to 0 are copied from the original message
        # - Set sender id and status
        data = [self.rorg] + \
               [enoceanjob.utils.from_bitarray([True, False] + response + [False, False, False, True])] + \
               self.data[2:8] + \
               sender_id + [0]

        # Always use 0x03 to indicate sending, attach sender ID, dBm, and security level
        optional = [0x03] + self.sender + [0xFF, 0x00]

        return RadioPacket(PACKET.RADIO_ERP1, data=data, optional=optional)

class SECTeachInPacket(RadioPacket):

    SLF=None
    RLC=[]
    KEY=[]
    IDX=None
    CNT=None
    PSK=None
    TYPE=None
    INFO=None

    @staticmethod
    def create_SECTI_chain(rorg=0x35, Key=None, RLC=None, SLF=None, PSK=0, TYPE=0, INFO=0,sender=None, destination=None):
        SLF_IN = security.SLF(SLF)

        if RLC == None:
            RLC = [0x00] * (SLF_IN.RLC_ALGO + 1)
        else:
            RLC = RLC[-(SLF_IN.RLC_ALGO + 1):]

        if sender is None:
            sender = [0x00] * 4
        
        if destination is None:
            destination = [0xFF] * 4

        if Key is None:
            Key = list(get_random_bytes(16))
            #Key = bytearray.fromhex("869FAB7D296C9E48CEBFF34DF637358A")

        data = [SLF] + RLC + Key #+ sender + [0x00]
        optional = [0x03] + destination + [0xFF, 0x00]

        sec_ti_list = []
        N = math.ceil(len(data)/8)
        PTI = (PSK << 3) | (TYPE << 2) | (INFO & 0x03)

        TINFO = (N << 4) | PTI
        assemble_packet = SECTeachInPacket(PACKET.RADIO_ERP1, data=[rorg] + [TINFO] + data + sender + [0x00],optional=optional)

        for i in range(N-1):
            idx = i << 6
            if i == 0:
                cnt = N << 4
            else:
                cnt=0
            TINFO = idx | cnt | PTI
            data_i = [rorg] + [TINFO] + data[i*8:i*8+8] + sender + [0x00]
            sec_ti_list.append(SECTeachInPacket(PACKET.RADIO_ERP1, data=data_i, optional=optional))

        data_last = [rorg] + [TINFO + 0x40] + data[-(len(data)%8):]  + sender + [0x00]
        sec_ti_list.append(SECTeachInPacket(PACKET.RADIO_ERP1, data=data_last, optional=optional))

        return sec_ti_list, assemble_packet
    
    def parse(self):
        self.IDX = self.data[1] >> 6
        self.CNT = (self.data[1] & 0x30) >> 4
        self.PSK = (self.data[1] & 0x08) >> 3
        self.TYPE = (self.data[1] & 0x04) >> 2
        self.INFO = self.data[1] & 0x03
        if len(self.data) > 15:
            SLF_IN = security.SLF(self.data[2])
            self.SLF = self.data[2]
            self.RLC = self.data[3:-21]
            self.KEY = self.data[-21:-5]
        return super(SECTeachInPacket, self).parse()





class ResponsePacket(Packet):
    response = 0
    response_data = []

    def parse(self):
        self.response = self.data[0]
        self.response_data = self.data[1:]
        return super(ResponsePacket, self).parse()


class EventPacket(Packet):
    event = 0
    event_data = []

    def parse(self):
        self.event = self.data[0]
        self.event_data = self.data[1:]
        return super(EventPacket, self).parse()
