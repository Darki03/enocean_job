# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import os
import logging
from sys import version_info
from collections import OrderedDict
from bs4 import BeautifulSoup

import enoceanjob.utils
from enoceanjob.protocol.constants import RORG


class EEP(object):
    logger = logging.getLogger('enoceanjob.protocol.eep')

    def __init__(self):
        self.init_ok = False
        self.telegrams = {}

        try:
            if version_info[0] > 2:
                with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'eep268.xml'), 'r', encoding='UTF-16LE') as xml_file:
                    xml_file.readline()
                    self.soup = BeautifulSoup(xml_file.read(), features='xml')
            else:
                with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'eep268.xml'), 'r') as xml_file:
                    xml_file.readline()
                    self.soup = BeautifulSoup(xml_file.read(), features='xml') #"html.parser")
            self.init_ok = True
            self.__load_xml()
        except IOError:
            # Impossible to test with the current structure?
            # To be honest, as the XML is included with the library,
            # there should be no possibility of ever reaching this...
            self.logger.warn('Cannot load protocol file!')
            self.init_ok = False

    def __load_xml(self):
        Profile = self.soup.profile
        self.telegrams = {
            enoceanjob.utils.from_hex_string(telegram.number.string): {
                enoceanjob.utils.from_hex_string(function.number.string): {
                    enoceanjob.utils.from_hex_string(type.number.string, ): type
                    for type in function.find_all('type', recursive=False)
                }
                for function in telegram.find_all('func', recursive=False)
            }
            for telegram in Profile.find_all(recursive=False)
        }

    @staticmethod
    def _get_raw(source, bitarray):
        ''' Get raw data as integer, based on offset and size '''
        offset = int(source.find('bitoffs').string)
        size = int(source.find('bitsize').string)
        return int(''.join(['1' if digit else '0' for digit in bitarray[offset:offset + size]]), 2)

    @staticmethod
    def _set_raw(target, raw_value, bitarray):
        ''' put value into bit array '''
        offset = int(target.find('bitoffs').string)
        size = int(target.find('bitsize').string)
        for digit in range(size):
            bitarray[offset+digit] = (raw_value >> (size-digit-1)) & 0x01 != 0
        return bitarray

    @staticmethod
    def _get_rangeitem(source, raw_value):
        for rangeitem in source.find_all('rangeitem'):
            if raw_value in range(int(rangeitem.get('start', -1)), int(rangeitem.get('end', -1)) + 1):
                return rangeitem

    def _get_value(self, source, bitarray):
        ''' Get value, based on the data in XML '''
        raw_value = self._get_raw(source, bitarray)

        rng = source.find('range')
        rng_min = float(rng.find('min').string)
        rng_max = float(rng.find('max').string)

        scl = source.find('scale')
        scl_min = float(scl.find('min').string)
        scl_max = float(scl.find('max').string)

        return {
            source.find('shortcut').string.strip(): {
                'description': source.find('description').string if source.find('description') is not None else "None",
                'unit': source.find('unit').string if source.find('unit') is not None else "None",
                'value': (scl_max - scl_min) / (rng_max - rng_min) * (raw_value - rng_min) + scl_min,
                'raw_value': raw_value,
            }
        }

    def _get_enum(self, source, bitarray):
        ''' Get enum value, based on the data in XML '''
        raw_value = self._get_raw(source, bitarray)
        descript = ""
        
        # Find value description.
        value_desc = source.find('value', string = str(raw_value))
        if value_desc is not None:
            for st in value_desc.find_next('description').stripped_strings: 
                descript = descript + st
                
        return {
            source.find('shortcut').string.strip(): {
                'description': source.find('description').string if source.find('description') is not None else "None",
                'unit': source.find('unit').string if source.find('unit') is not None else "None",
                'value': descript,
                'raw_value': raw_value,
            }
        }

    def _get_boolean(self, source, bitarray):
        ''' Get boolean value, based on the data in XML '''
        raw_value = self._get_raw(source, bitarray)
        return {
            source.find('data').string.strip(): {
                'description': source.find('description').string  if source.find('description') is not None else "None",
                'unit': source.find('unit').string if source.find('unit') is not None else "None",
                'value': True if raw_value else False,
                'raw_value': raw_value,
            }
        }

    def _set_value(self, target, value, bitarray):
        ''' set given numeric value to target field in bitarray '''
        # derive raw value
        rng = target.find('range')
        rng_min = float(rng.find('min').string)
        rng_max = float(rng.find('max').string)
        scl = target.find('scale')
        scl_min = float(scl.find('min').string)
        scl_max = float(scl.find('max').string)
        raw_value = (value - scl_min) * (rng_max - rng_min) / (scl_max - scl_min) + rng_min
        # store value in bitfield
        return self._set_raw(target, int(raw_value), bitarray)

    def _set_enum(self, target, value, bitarray):
        ''' set given enum value (by string or integer value) to target field in bitarray '''
        # derive raw value
        if isinstance(value, int):
            # check whether this value exists
            if target.find('value', string = str(value)) or self._get_rangeitem(target, value):
                # set integer values directly
                raw_value = value
            else:
                raise ValueError('Enum value "%s" not found in EEP.' % (value))
        else:
            value_item = target.find('description', string = str(value))
            if value_item is None:
                raise ValueError('Enum description for value "%s" not found in EEP.' % (value))
            raw_value = int(value_item.find_previous('value').string)
        return self._set_raw(target, raw_value, bitarray)

    @staticmethod
    def _set_boolean(target, data, bitarray):
        ''' set given value to target bit in bitarray '''
        bitarray[int(target.find('offset').string)] = data
        return bitarray

    def find_case(self, profile, bitarray, mid = None):
        cond = []
        Case = None
        Conditions = profile.find_all('condition')
        
        for fields in Conditions:
            for cond_type in fields:

                if cond_type.name == 'datafield':
                    offset = int(cond_type.find('bitoffs').string)
                    size = int(cond_type.find('bitsize').string)
                    if mid is None:
                        raw_cond = int(''.join(['1' if digit else '0' for digit in bitarray[offset:offset + size]]), 2)
                    else:
                        raw_cond = mid
                    val = cond_type.find('value', string = str(raw_cond))
                    cond.append(val.string if val is not None else None)

                if cond_type.name == 'statusfield':
                    offset = int(cond_type.find('bitoffs').string)
                    size = int(cond_type.find('bitsize').string)
                    if mid is None:
                        raw_cond = int(''.join(['1' if digit else '0' for digit in bitarray[offset:offset + size]]), 2)
                    else:
                        raw_cond = mid
                    cond.append(cond_type.find('value', string = str(raw_cond)))
                
                if None in cond:
                    cond.clear()
                else:
                    Case = fields.find_parent('case')
                    break
        
        if Case is not None:
            # return Case.find_all(['datafield', 'statusfield'])
            return Case
        else:
            self.logger.warn('Cannot find condition in the message!')
            return None

    
    def find_profile(self, bitarray, bitstatus, eep_rorg, rorg_func, rorg_type, direction=None, command=None, mid=None):
        ''' Find profile and data description, matching RORG, FUNC and TYPE '''
        if not self.init_ok:
            self.logger.warn('EEP.xml not loaded!')
            return None

        if eep_rorg not in self.telegrams.keys():
            self.logger.warn('Cannot find rorg in EEP!')
            return None

        if rorg_func not in self.telegrams[eep_rorg].keys():
            self.logger.warn('Cannot find func in EEP!')
            return None

        if rorg_type not in self.telegrams[eep_rorg][rorg_func].keys():
            self.logger.warn('Cannot find type in EEP!')
            return None

        profile = self.telegrams[eep_rorg][rorg_func][rorg_type]
        
        if command:
            # multiple commands can be defined, with the command id always in same location (per RORG-FUNC-TYPE).
            eep_command = profile.find('command', recursive=False)
            # If commands are not set in EEP, or command is None,
            # get the first data as a "best guess".
            if not eep_command:
                return profile.find('data', recursive=False)

            # If eep_command is defined, so should be data.command
            return profile.find('data', {'command': str(command)}, recursive=False)

        #If Type is conditionnal
        if profile.find('condition') is not None:
            # print(self.find_case(profile, bitarray, mid))
            # return self.find_case(profile, bitarray, mid)
            cond = []
            Case = None
            Conditions = profile.find_all('condition')
            for fields in Conditions:
                for cond_type in fields:
                    if cond_type.name == 'datafield':
                        offset = int(cond_type.find('bitoffs').string)
                        size = int(cond_type.find('bitsize').string)
                        raw_cond = int(''.join(['1' if digit else '0' for digit in bitarray[offset:offset + size]]), 2)
                        if mid: raw_cond=mid
                        val = cond_type.find('value', string = str(raw_cond))
                        cond.append(val.string if val is not None else None)

                    if cond_type.name == 'statusfield':
                        offset = int(cond_type.find('bitoffs').string)
                        size = int(cond_type.find('bitsize').string)
                        raw_cond = int(''.join(['1' if digit else '0' for digit in bitstatus[offset:offset + size]]), 2)
                        val = cond_type.find('value', string = str(raw_cond))
                        cond.append(val.string if val is not None else None)

                if None in cond:
                    cond.clear()
                else:
                    Case = fields.find_parent('case')
                    break

            if Case is not None:
                return Case
            else:
                self.logger.warn('Cannot find condition in the message!')
                return None
                
        # extract data description
        # the direction tag is optional
        if direction is None:
            return profile.find('case')
        
        return profile.find('case')

    def get_values(self, profile, bitarray, status):
        ''' Get keys and values from bitarray '''
        if not self.init_ok or profile is None:
            return [], {}

        output = OrderedDict({})
        for source in profile.find_all(['datafield', 'statusfield']):
            if source.name == 'statusfield':
                 if source.find('data') is not None:
                    output.update(self._get_boolean(source, status))

            if source.name == 'datafield':
                for data in source:
                    if not data.name:
                        continue
                    if data.name == 'range':
                        output.update(self._get_value(source, bitarray))
                    if data.name == 'enum':
                        output.update(self._get_enum(source, bitarray))
        return output.keys(), output

    def set_values(self, profile, data, status, properties):
        ''' Update data based on data contained in properties '''
        if not self.init_ok or profile is None:
            return data, status
        
        for shortcut, value in properties.items():

            for item in profile.find_all(['datafield', 'statusfield']):
            # find the given property from EEP      
                
                target = item.find('shortcut', string = str(shortcut))
                if target:
                    # # TODO: Should we raise an error?
                    # self.logger.warning('Cannot find data description for shortcut %s', shortcut)
                    # continue
                    
                    if item.name == 'statusfield':
                        data = self._set_boolean(item, value, status)

                    if item.name == 'datafield':
                        for fields in item:
                            
                            # update bit_data
                            if fields.name == 'enum':

                                data = self._set_enum(item, value, data)
                            if fields.name == 'range':
                                data = self._set_value(item, value, data)
        
        return data, status
