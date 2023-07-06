from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import CMAC
import bitstring
from enoceanjob.protocol.security import CMAC_calc



K             = bytearray.fromhex("869FAB7D296C9E48CEBFF34DF637358A")
M             = list(bytearray.fromhex("315D919D0B3AF002"))
CMAC_telegram = bytearray.fromhex("7F4E22")
RLC           = list(bytearray.fromhex("000CEC"))
#Decrypt_message : 8400000A1B40
#RLC: 00000CEC

MAC2 = CMAC_calc(K, M, RLC,3)


#***********************Display****************************#
assert MAC2 == CMAC_telegram
print("CMAC_lib = " + bytes(MAC2).hex())
#*********************************************************************#
