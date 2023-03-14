# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import

import math
import bitstring
import enoceanjob.utils
import ctypes
from Crypto.Cipher import AES
from enoceanjob.protocol.constants import PACKET, RORG, SLF_INFO

c_uint8 = ctypes.c_uint8

class SLF_FIELDS(ctypes.BigEndianStructure):
    _fields_ = [
            ("RLC_ALGO", c_uint8, 2),
            ("RLC_TX", c_uint8, 1),
            ("MAC_ALGO", c_uint8, 2),
            ("DATA_ENC", c_uint8, 3),
        ]

class SLF_FIELDS_U(ctypes.Union):
    _fields_ = [("b", SLF_FIELDS),
                ("asbyte", c_uint8)]

class SLF(object):

    def __init__(self, SLF_value):
        SLF = SLF_FIELDS_U()
        SLF.asbyte = SLF_value
        self.RLC_ALGO = SLF.b.RLC_ALGO
        self.RLC_TX = SLF.b.RLC_TX
        self.MAC_ALGO = SLF.b.MAC_ALGO
        self.DATA_ENC = SLF.b.DATA_ENC



def CMAC_calc(K, Message, RLC, CMAC_size):
    
    #Constants
    Const_zero = bytearray.fromhex("00000000000000000000000000000000")
    Const_Rb   = bytearray.fromhex("00000000000000000000000000000087")
    Const_BlSize = 16
    
    #Concatenate Rolling Code
    Message = Message + RLC
    
    #*************** Generate subkeys**************************************#
    cipher = AES.new(K, AES.MODE_ECB)
    L = cipher.encrypt(Const_zero) #AES128 on Const_Zero with Key

    #Compute K1
    if bitstring.BitArray(L)[0] == 0: #if MSBit(L) = 0
        K1 = bitstring.BitArray(L) << 1
    else:
        K1 = (bitstring.BitArray(L) << 1) ^ bitstring.BitArray(Const_Rb)

    #Compute K2
    if K1[0] == 0:
        K2 = bitstring.BitArray(K1) << 1
    else:
        K2 = (bitstring.BitArray(K1) << 1) ^ bitstring.BitArray(Const_Rb)
    #*********************************************************************#
    
    #Blocks management and CMAC computation
    N = math.ceil(len(Message)/Const_BlSize)
    
    if N == 0:
        N = 1
        Flag = 0
    else:
        if len(Message)%16 ==0:
            Flag = 1
        else:
            Flag = 0
    
    M_last = []
    Start = len(Message) - (len(Message)%16)
    M_last = Message[Start:len(Message)]
    if Flag == 1:
        for i in range(len(M_last)):
            M_last[i] = M_last[i] ^ K1.tobytes()[i]
    else:
        M_last = M_last + list(bitstring.BitArray(bin=str(pow(10 ,(128-8*len(M_last)-1)))).bytes)
        for i in range(len(M_last)):
            M_last[i] = M_last[i] ^ K2.tobytes()[i]
    
    X = Const_zero
    Y = Const_zero
    for i in range(N-1):
        M_i = Message[i*16:i*16+16]
        for i in range(len(M_i)):
            Y[i] = M_i[i] ^ X[i]
        X = cipher.encrypt(Y)
    
    for i in range(len(M_last)):
        Y[i] = M_last[i] ^ X[i]
    T = cipher.encrypt(Y)

    return T[0:CMAC_size]

#Function for retreiving rolling code frome CMAC (RLC not transmitted)
# K = Secure Key
# Data_CMAC = List of Data used for CMAC calculation
# CMAC_in = Received CMAC
# RLC_in = RLC search start value
# WS = Window Size for RLC research
def find_RLC(K, Data_CMAC, CMAC_in, RLC_in, WS):
    
    int_RLC_in = enoceanjob.utils.combine_hex(RLC_in)
    for i in range(int_RLC_in, int_RLC_in + WS):
        RLC_test = list(i.to_bytes(len(RLC_in), byteorder='big'))
        Test_CMAC = CMAC_calc(K, Data_CMAC, RLC_test, len(CMAC_in))
        if list(Test_CMAC) == CMAC_in:
            return RLC_test
    return None

def VAES128(Key, Data_enc = [], RLC = []):
    INIT_VEC = bytearray.fromhex("3410de8f1aba3eff9f5a117172eacabd")
    IV = INIT_VEC

    # INIT_VEC XOR RLC
    for i in range(len(RLC)):
        IV[i] = IV[i] ^ RLC[i]

    #Encrypt IV XOR RLC
    cipher = AES.new(Key, AES.MODE_ECB)
    ENC = cipher.encrypt(IV)

    #ENC XOR Data_enc
    for i in range(len(Data_enc)):
       Data_enc[i] = Data_enc[i] ^ ENC[i]

    return Data_enc
    