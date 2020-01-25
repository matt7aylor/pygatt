"""
MODIFIED BGAPI/BGLib implementation for BGAPI v2
based on original work detailed below and modifications made in pygatt
============================================
Bluegiga BGLib Python interface library
2013-05-04 by Jeff Rowberg <jeff@rowberg.net>
Updates should (hopefully) always be available at
https://github.com/jrowberg/bglib
Thanks to Masaaki Shibata for Python event handler code
http://www.emptypage.jp/notes/pyevent.en.html
============================================
BGLib Python interface library code is placed under the MIT license
Copyright (c) 2013 Jeff Rowberg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
===============================================
"""

from __future__ import print_function

import logging
from struct import unpack
from enum import Enum

log = logging.getLogger(__name__)


class UnknownMessageType(Exception):
    pass


ResponsePacketType = Enum('ResponsePacketType', [
    ### system ###
    'system_reset',
    'system_hello',
    'system_get_bt_address',
    'system_get_counters', # New form, needs updating

    # New commands XXX To implement (bglib.py and packets.py)
    # 'system_data_buffer_clear',
    # 'system_data_buffer_write',
    # 'system_get_random_data',
    # 'system_halt',
    # 'system_linklayer_configure',
    # 'system_set_device_name',
    # 'system_set_identity_address',
    # 'system_set_tx_power',

    # No longer present?
    #'system_reg_write', # Not present?
    #'system_reg_read', # Not present?
    #'system_get_connections', # Not present?
    #'system_read_memory', # Not present?
    #'system_get_info', # Not present?
    #'system_endpoint_tx', # Not present?
    # 'system_whitelist_append', # Not present?
    # 'system_whitelist_remove', # Not present?
    # 'system_whitelist_clear', # Not present?
    # 'system_endpoint_rx', # Not present?
    # 'system_endpoint_set_watermarks', # Not present?

    ### flash ###
    'flash_ps_erase_all',
    'flash_ps_save',
    'flash_ps_load',
    'flash_ps_erase',

    # Old removed commands
    # 'flash_ps_defrag',
    # 'flash_ps_dump',
    # 'flash_erase_page',
    # 'flash_write_words',


    # gatt #

    # read
    'gatt_read_characteristic_value',
    #'gatt_read_characteristic_value_by_uuid',
    #'gatt_read_characteristic_value_from_offset',

    # write
    'gatt_write_characteristic_value',
    #'gatt_write_characteristic_value_without_response'
    #'gatt_write_descriptor_value',


    ### gatt ### XXX Mostly new section, replaces attclient?
    'attclient_find_information',   # XXX
    'attclient_read_by_handle',     # XXX
    'attclient_attribute_write',    # XXX
    'attclient_write_command',      # XXX
    'attclient_read_long',          # XXX
    'attclient_prepare_write',      # XXX
    'attclient_execute_write',      # XXX

    # New commands
    # 'gatt_discover_characteristics_by_uuid',
    # 'gatt_discover_primary_services_by_uuid',
    'gatt_discover_primary_services',
    'gatt_discover_characteristics',
    'gatt_discover_descriptors',



    # Old removed commands
    # 'attclient_find_by_type_value',
    # 'attclient_read_by_type',
    # 'attclient_read_by_group_type',
    # 'attclient_indicate_confirm',
    # 'attclient_read_multiple',

    ### gatt_server ### XXX Mostly new, replaces attribute database?
    'attributes_write',
    'attributes_read',
    'attributes_read_type',
    'attributes_user_read_response',
    'attributes_user_write_response',
    # New commands
    # XXX


    ### hardware ### Total change XXX

    # Old removed commands
    # 'hardware_io_port_config_irq',
    # 'hardware_set_soft_timer',
    # 'hardware_adc_read',
    # 'hardware_io_port_config_direction',
    # 'hardware_io_port_config_function',
    # 'hardware_io_port_config_pull',
    # 'hardware_io_port_write',
    # 'hardware_io_port_read',
    # 'hardware_spi_config',
    # 'hardware_spi_transfer',
    # 'hardware_i2c_read',
    # 'hardware_i2c_write',
    # 'hardware_set_txpower',
    # 'hardware_timer_comparator',

    ### le_connection ### Similar to connection XXX
    'le_connection_close',
    'connection_get_rssi',          # XXX
    'connection_update',
    'connection_version_update',
    'connection_channel_map_get',
    'connection_channel_map_set',
    # 'connection_features_get',
    'connection_get_status',
    'connection_raw_tx',

    ### le_gap ### Similar to original, some changed and new commands XXX
    'le_gap_set_scan_parameters',   # XXX DEPRECATED
    'le_gap_end_procedure',
    'le_gap_set_mode',                 # XXX DEPRECATED
    'le_gap_discover',                 # XXX DEPRECATED
    'le_gap_connect',           # XXX
    'gap_set_privacy_flags',
    'gap_connect_selective',
    'gap_set_filtering',
    'gap_set_adv_parameters',
    'gap_set_adv_data',
    'gap_set_directed_connectable_mode',

    ### smm ### Similar to original XXX
    'sm_encrypt_start',             # XXX
    'sm_set_bondable_mode',         # XXX Done?
    'sm_delete_bonding',            # XXX
    'sm_set_parameters',
    'sm_passkey_entry',
    'sm_get_bonds',                 # XXX
    'sm_set_oob_data',

    ### test ### Some changes XXX
    # Old removed commands
    # 'test_phy_tx',
    # 'test_phy_rx',
    # 'test_phy_end',
    # 'test_phy_reset',
    # 'test_get_channel_map',
    # 'test_debug',
])


EventPacketType = Enum('EventPacketType', [
    ### system ###
    'system_boot',
    # New events
    # 'system_external_signal',
    # 'system_awake',
    # 'system_hardware_error',
    'system_error',

    # Old removed
    # 'system_debug',
    # 'system_endpoint_watermark_rx',
    # 'system_endpoint_watermark_tx',
    # 'system_script_failure',
    # 'system_no_license_key',

    ### flash - Old removed###
    # 'flash_ps_key',

    ### gatt-server ###
    'gatt_server_attribute_value',
    'gatt_server_user_read_request',
    'gatt_server_characteristic_status',
    # New events
    # 'gatt_server_user_write_request',
    # 'gatt_server_execute_write_completed',

    ### le-connection
    'le_connection_parameters',                    # XXX Partially done, need to check where it is used
    # New events
    'le_connection_opened',                # XXX new expectation on connect
    'le_connection_closed',                # XXX new expectation on disconnect
    'le_connection_rssi',
    'le_connection_phy_status',
    # Old removed
    # 'connection_version_ind',
    # 'connection_feature_ind',
    # 'connection_raw_rx',

    ### gatt ###
    'gatt_service',
    'attclient_procedure_completed',        # XXX
    'attclient_find_information_found',     # XXX
    'attclient_attribute_value',            # XXX
    # New events
    'gatt_mtu_exchanged',                   # XXX What if MTU changes?
    'gatt_characteristic',
    'gatt_procedure_completed',
    'gatt_descriptor',
    'gatt_characteristic_value',
    'gatt_descriptor_value',
    # Old removed
    # 'attclient_indicated',
    # 'attclient_read_multiple_response',
    # 'attclient_attribute_found',

    ### sm ###
    'sm_passkey_display',
    'sm_passkey_request',
    'sm_bonding_fail',                      # XXX
    'sm_bond_status',                       # XXX
    # New events
    # 'sm_confirm_passkey',
    # 'sm_bonded',                           # XXX
    # 'sm_list_bonding_entry',
    # 'sm_list_all_bondings_complete',
    # 'sm_confirm_bonding',
    # Old removed
    # 'sm_smp_data',

    ### le-gap ###
    'le_gap_scan_response',                    # XXX
    # New events
    # 'le_gap_adv_timeout',
    # 'le_gap_scan_request',
    # 'le_gap_extended_scan_response',
    # Old removed
    # 'gap_mode_changed',

    ### hardware ###
    'hardware_soft_timer',
    # Old removed
    # 'hardware_io_port_status',
    # 'hardware_adc_result',
])

# Map a tuple of (class, command) to an enum identifier for the packet
RESPONSE_PACKET_MAPPING = {
    (1, 1): ResponsePacketType.system_reset,
    (1, 0): ResponsePacketType.system_hello,
    (1, 3): ResponsePacketType.system_get_bt_address,
    # (0, 3): ResponsePacketType.system_reg_write,
    # (0, 4): ResponsePacketType.system_reg_read,
    (1, 0x0f): ResponsePacketType.system_get_counters,
    # (0, 6): ResponsePacketType.system_get_connections,
    # (0, 7): ResponsePacketType.system_read_memory,
    # (0, 8): ResponsePacketType.system_get_info,
    # (0, 9): ResponsePacketType.system_endpoint_tx,
    # (0, 10): ResponsePacketType.system_whitelist_append,
    # (0, 11): ResponsePacketType.system_whitelist_remove,
    # (0, 12): ResponsePacketType.system_whitelist_clear,
    # (0, 13): ResponsePacketType.system_endpoint_rx,
    # (0, 14): ResponsePacketType.system_endpoint_set_watermarks,

    # (1, 1): ResponsePacketType.flash_ps_dump,
    (0x0d, 1): ResponsePacketType.flash_ps_erase_all,
    (0x0d, 2): ResponsePacketType.flash_ps_save,
    (0x0d, 3): ResponsePacketType.flash_ps_load,
    (0x0d, 4): ResponsePacketType.flash_ps_erase,
    # (1, 6): ResponsePacketType.flash_erase_page,
    # (1, 7): ResponsePacketType.flash_write_words,

    (2, 0): ResponsePacketType.attributes_write,
    (2, 1): ResponsePacketType.attributes_read,
    (2, 2): ResponsePacketType.attributes_read_type,
    (2, 3): ResponsePacketType.attributes_user_read_response,
    (2, 4): ResponsePacketType.attributes_user_write_response,

    (0x08, 0x04): ResponsePacketType.le_connection_close,
    #(3, 1): ResponsePacketType.connection_get_rssi,
    # (3, 2): ResponsePacketType.connection_update,
    #(3, 3): ResponsePacketType.connection_version_update,
    (3, 4): ResponsePacketType.connection_channel_map_get,
    (3, 5): ResponsePacketType.connection_channel_map_set,
    # (3, 6): ResponsePacketType.connection_features_get,
    (3, 7): ResponsePacketType.connection_get_status,
    (3, 8): ResponsePacketType.connection_raw_tx,

    # (4, 0): ResponsePacketType.attclient_find_by_type_value,
    # (4, 1): ResponsePacketType.attclient_read_by_group_type,
    # (4, 2): ResponsePacketType.attclient_read_by_type,
    (4, 3): ResponsePacketType.attclient_find_information,
    (4, 4): ResponsePacketType.attclient_read_by_handle,
    (4, 5): ResponsePacketType.attclient_attribute_write,
    (4, 6): ResponsePacketType.attclient_write_command,
    # (4, 7): ResponsePacketType.attclient_indicate_confirm,
    (4, 8): ResponsePacketType.attclient_read_long,
    (4, 9): ResponsePacketType.attclient_prepare_write,
    (4, 10): ResponsePacketType.attclient_execute_write,

    (5, 0): ResponsePacketType.sm_encrypt_start,
    (0x0f, 0): ResponsePacketType.sm_set_bondable_mode,
    (5, 2): ResponsePacketType.sm_delete_bonding,
    (5, 3): ResponsePacketType.sm_set_parameters,
    (5, 4): ResponsePacketType.sm_passkey_entry,
    (5, 5): ResponsePacketType.sm_get_bonds,
    (5, 6): ResponsePacketType.sm_set_oob_data,

    (6, 0): ResponsePacketType.gap_set_privacy_flags,
    (3, 1): ResponsePacketType.le_gap_set_mode,
    (3, 2): ResponsePacketType.le_gap_discover,
    (3, 0x1a): ResponsePacketType.le_gap_connect,
    (3, 3): ResponsePacketType.le_gap_end_procedure,
    (6, 5): ResponsePacketType.gap_connect_selective,
    (6, 6): ResponsePacketType.gap_set_filtering,
    (3, 6): ResponsePacketType.le_gap_set_scan_parameters,
    (6, 8): ResponsePacketType.gap_set_adv_parameters,
    (6, 9): ResponsePacketType.gap_set_adv_data,
    (6, 10): ResponsePacketType.gap_set_directed_connectable_mode,

    # (7, 0): ResponsePacketType.hardware_io_port_config_irq,
    # (7, 1): ResponsePacketType.hardware_set_soft_timer,
    # (7, 2): ResponsePacketType.hardware_adc_read,
    # (7, 3): ResponsePacketType.hardware_io_port_config_direction,
    # (7, 4): ResponsePacketType.hardware_io_port_config_function,
    # (7, 5): ResponsePacketType.hardware_io_port_config_pull,
    # (7, 6): ResponsePacketType.hardware_io_port_write,
    # (7, 7): ResponsePacketType.hardware_io_port_read,
    # (7, 8): ResponsePacketType.hardware_spi_config,
    # (7, 9): ResponsePacketType.hardware_spi_transfer,
    # (7, 10): ResponsePacketType.hardware_i2c_read,
    # (7, 11): ResponsePacketType.hardware_i2c_write,
    # (7, 12): ResponsePacketType.hardware_set_txpower,
    # (7, 13): ResponsePacketType.hardware_timer_comparator,

    # (8, 0): ResponsePacketType.test_phy_tx,
    # (8, 1): ResponsePacketType.test_phy_rx,
    # (8, 2): ResponsePacketType.test_phy_reset,
    # (8, 3): ResponsePacketType.test_get_channel_map,
    # (8, 4): ResponsePacketType.test_debug,

    (9, 1): ResponsePacketType.gatt_discover_primary_services,
    (9, 3): ResponsePacketType.gatt_discover_characteristics,
    (9, 6): ResponsePacketType.gatt_discover_descriptors,
    (9, 7): ResponsePacketType.gatt_read_characteristic_value,
    (9, 9): ResponsePacketType.gatt_write_characteristic_value


}

# TODO instead of this, have a different enum for each message type + class, and
# then just index into it

EVENT_PACKET_MAPPING = {
    (1, 0): EventPacketType.system_boot,
    (1, 6) : EventPacketType.system_error,
    # (0, 1): EventPacketType.system_debug,
    # (0, 2): EventPacketType.system_endpoint_watermark_rx,
    # (0, 3): EventPacketType.system_endpoint_watermark_tx,
    # (0, 4): EventPacketType.system_script_failure,
    # (0, 5): EventPacketType.system_no_license_key,

    # (1, 0): EventPacketType.flash_ps_key,

    (0x0a, 0): EventPacketType.gatt_server_attribute_value,
    (0x0a, 1): EventPacketType.gatt_server_user_read_request,
    (0x0a, 3): EventPacketType.gatt_server_characteristic_status,

    (0x08, 0): EventPacketType.le_connection_opened,
    (0x08, 1): EventPacketType.le_connection_closed,
    (0x08, 2): EventPacketType.le_connection_parameters,
    (0x08, 3): EventPacketType.le_connection_rssi,
    (0x08, 4): EventPacketType.le_connection_phy_status,
    # (3, 1): EventPacketType.connection_version_ind,
    # (3, 2): EventPacketType.connection_feature_ind,
    # (3, 3): EventPacketType.connection_raw_rx,

    (9, 0): EventPacketType.gatt_mtu_exchanged,
    (9, 1): EventPacketType.gatt_service,
    (9, 2): EventPacketType.gatt_characteristic,
    (9, 3): EventPacketType.gatt_descriptor,
    (9, 4): EventPacketType.gatt_characteristic_value,
    (9, 5): EventPacketType.gatt_descriptor_value,
    (9, 6): EventPacketType.gatt_procedure_completed,

    # (4, 0): EventPacketType.attclient_indicated,
    (4, 1): EventPacketType.attclient_procedure_completed,
    # (4, 3): EventPacketType.attclient_attribute_found,
    (4, 4): EventPacketType.attclient_find_information_found,
    (4, 5): EventPacketType.attclient_attribute_value,
    # (4, 6): EventPacketType.attclient_read_multiple_response,

    # (5, 0): EventPacketType.sm_smp_data,
    (5, 1): EventPacketType.sm_bonding_fail,
    (0x0f, 0): EventPacketType.sm_passkey_display,
    (0x0f, 1): EventPacketType.sm_passkey_request,
    (5, 4): EventPacketType.sm_bond_status,

    (3, 0): EventPacketType.le_gap_scan_response,
    # (6, 1): EventPacketType.gap_mode_changed,

    # (7, 0): EventPacketType.hardware_io_port_status,
    (0x0c, 0): EventPacketType.hardware_soft_timer,
    # (7, 2): EventPacketType.hardware_adc_result,

}


class BGLib(object):
    """
    Modified version of jrowberg's BGLib implementation.
    """
    def __init__(self):
        self.buffer = []
        self.expected_length = 0
        # Packet message types
        self._ble_event = 0xa0
        self._ble_response = 0x20
        self._wifi_event = 0x88 # Remove? XXX
        self._wifi_response = 0x08 # Remove? XXX

    def send_command(self, ser, packet):
        """
        Send a packet to the BLED12 over serial.

        ser -- The serial.Serial object to write to.
        packet -- The packet to write.
        """
        print("Sending:", packet)  # XXX DEBUG XXX
        ser.write(packet)

    def parse_byte(self, new_byte):
        """
        Re-build packets read in from bytes over serial one byte at a time.

        new_byte -- the next bytes to add to the packet.

        Returns a list of the bytes in the packet once a full packet is read.
        Returns None otherwise.
        """
        if new_byte is None or len(new_byte) == 0:
            return None

        # Convert from str or bytes to an integer for comparison
        new_byte = ord(new_byte)

        if (len(self.buffer) == 0 and
                new_byte in [self._ble_event, self._ble_response,
                             self._wifi_event, self._wifi_response]):
            self.buffer.append(new_byte)
        elif len(self.buffer) == 1:
            self.buffer.append(new_byte)
            self.expected_length = (
                4 + (self.buffer[0] & 0x07) + self.buffer[1])
        elif len(self.buffer) > 1:
            self.buffer.append(new_byte)

        if (self.expected_length > 0 and
                len(self.buffer) == self.expected_length):
            packet = self.buffer
            self.buffer = []
            return packet

        return None

    def _decode_response_packet(self, packet_class, packet_command, payload,
                                payload_length):
        packet_type = RESPONSE_PACKET_MAPPING.get(
            (packet_class, packet_command))
        if packet_type is None:
            raise UnknownMessageType(
                "Packet class %d and command %d is not recognized" %
                (packet_class, packet_command))

        response = {}
        if packet_type == ResponsePacketType.system_get_bt_address:
            address = unpack('<6B', payload[:6])
            response = {
                'address': address
            }
        # elif packet_type == ResponsePacketType.system_reg_read:
            # address, value =\
                # unpack('<HB', payload[:3])
            # response = {
                # 'address': address, 'value': value
            # }
        elif packet_type == ResponsePacketType.system_get_counters: # XXX Needs update
            txok, txretry, rxok, rxfail, mbuf =\
                unpack('<BBBBB', payload[:5])
            response = {
                'txok': txok, 'txretry': txretry, 'rxok': rxok,
                'rxfail': rxfail, 'mbuf': mbuf
            }
        # elif packet_type == ResponsePacketType.system_get_connections:
            # maxconn = unpack('<B', payload[:1])[0]
            # response = {
                # 'maxconn': maxconn
            # }
        # elif packet_type == ResponsePacketType.system_read_memory:
            # address, data_len = unpack('<IB', payload[:5])
            # data_data = bytearray(payload[5:])
            # response = {
                # 'address': address, 'data': data_data
            # }
        # elif packet_type == ResponsePacketType.system_get_info:
            # data = unpack('<HHHHHBB', payload[:12])
            # response = {
                # 'major': data[0], 'minor': data[1],
                # 'patch': data[2], 'build': data[3],
                # 'll_version': data[4], 'protocol_version': data[5],
                # 'hw': data[6]
            # }
        elif packet_type in [
                ResponsePacketType.le_connection_close,
                # ResponsePacketType.system_endpoint_tx,
                # ResponsePacketType.system_whitelist_append,
                # ResponsePacketType.system_whitelist_remove,
                # ResponsePacketType.system_endpoint_set_watermarks,
                ResponsePacketType.flash_ps_save,
                # ResponsePacketType.flash_erase_page,
                ResponsePacketType.attributes_write,
                # ResponsePacketType.system_reg_write,
                # ResponsePacketType.attclient_indicate_confirm,
                ResponsePacketType.sm_delete_bonding,
                ResponsePacketType.sm_passkey_entry,
                ResponsePacketType.sm_set_bondable_mode,
                ResponsePacketType.le_gap_set_mode,
                ResponsePacketType.le_gap_discover,
                ResponsePacketType.le_gap_end_procedure,
                ResponsePacketType.gap_set_filtering,
                # ResponsePacketType.hardware_timer_comparator,
                # ResponsePacketType.test_phy_end,
                # ResponsePacketType.hardware_spi_config,
                ResponsePacketType.le_gap_set_scan_parameters,
                ResponsePacketType.gap_set_adv_parameters,
                ResponsePacketType.gap_set_adv_data,
                ResponsePacketType.gap_set_directed_connectable_mode,
                # ResponsePacketType.hardware_io_port_config_irq,
                # ResponsePacketType.hardware_set_soft_timer,
                # ResponsePacketType.hardware_adc_read,
                # ResponsePacketType.hardware_io_port_config_direction,
                # ResponsePacketType.hardware_io_port_config_function,
                # ResponsePacketType.hardware_io_port_config_pull,
                # ResponsePacketType.hardware_io_port_write
                ]:
            result = unpack('<H', payload[:2])[0]
            response = {
                'result': result
            }
        # elif packet_type == ResponsePacketType.system_endpoint_rx:
            # result, data_len =\
                # unpack('<HB', payload[:3])
            # data_data = bytearray(payload[3:])
            # response = {
                # 'result': result, 'data': data_data
            # }
        elif packet_type == ResponsePacketType.flash_ps_load:
            result, value_len = unpack('<HB',
                                       payload[:3])
            value_data = bytearray(payload[3:])
            response = {
                'result': result, 'value': value_data
            }
        elif packet_type == ResponsePacketType.attributes_read:
            handle, offset, result, value_len = unpack(
                '<HHHB', payload[:7]
            )
            value_data = bytearray(payload[7:])
            response = {
                'handle': handle, 'offset': offset,
                'result': result, 'value': value_data
            }
        elif packet_type == ResponsePacketType.attributes_read_type:
            handle, result, value_len = unpack(
                '<HHB', payload[:5]
            )
            value_data = bytearray(payload[5:])
            response = {
                'handle': handle, 'result': result,
                'value': value_data
            }
        elif packet_type in [
            ResponsePacketType.connection_update,
            ResponsePacketType.connection_version_update,
            ResponsePacketType.connection_channel_map_set,
            # ResponsePacketType.connection_features_get,
            # ResponsePacketType.attclient_find_by_type_value,
            # ResponsePacketType.attclient_read_by_group_type,
            # ResponsePacketType.attclient_read_by_type,
            ResponsePacketType.attclient_find_information,
            ResponsePacketType.attclient_read_by_handle,
            ResponsePacketType.attclient_attribute_write,
            ResponsePacketType.attclient_write_command,
            ResponsePacketType.attclient_read_long,
            ResponsePacketType.attclient_prepare_write,
            ResponsePacketType.attclient_execute_write,
            # ResponsePacketType.attclient_read_multiple,
        ]:
            connection, result = unpack(
                '<BH', payload[:3]
            )
            response = {
                'connection_handle': connection, 'result': result
            }
        elif packet_type == ResponsePacketType.connection_get_rssi:
            connection, rssi = unpack(
                '<Bb', payload[:2]
            )
            response = {
                'connection_handle': connection, 'rssi': rssi
            }
        elif packet_type == ResponsePacketType.connection_channel_map_get:
            connection, map_len = unpack(
                '<BB', payload[:2]
            )
            map_data = bytearray(payload[2:])
            response = {
                'connection_handle': connection, 'map': map_data
            }
        elif packet_type == ResponsePacketType.connection_get_status:
            connection = unpack('<B', payload[:1])[0]
            response = {
                'connection_handle': connection
            }
        elif packet_type == ResponsePacketType.connection_raw_tx:
            connection = unpack('<B', payload[:1])[0]
            response = {
                'connection_handle': connection
            }
        elif packet_type == ResponsePacketType.sm_encrypt_start:
            handle, result = unpack(
                '<BH', payload[:3]
            )
            response = {
                'handle': handle, 'result': result
            }
        elif packet_type == ResponsePacketType.sm_get_bonds:
            bonds = unpack('<B', payload[:1])[0]
            response = {
                'bonds': bonds
            }
        elif packet_type == ResponsePacketType.le_gap_connect:
            result, connection_handle = unpack(
                '<HB', payload[:3]
            )
            response = {
                'result': result,
                'connection_handle': connection_handle
            }
        elif packet_type == ResponsePacketType.gap_connect_selective:
            result, connection_handle = unpack(
                '<HB', payload[:3]
            )
            response = {
                'result': result,
                'connection_handle': connection_handle
            }
        # elif packet_type == ResponsePacketType.hardware_io_port_read:
            # result, port, data = unpack(
                # '<HBB', payload[:4]
            # )
            # response = {
                # 'result': result, 'port': port, 'data': data
            # }
        # elif packet_type == ResponsePacketType.hardware_spi_transfer:
            # result, channel, data_len = unpack(
                # '<HBB', payload[:4]
            # )
            # data_data = bytearray(payload[4:])
            # response = {
                # 'result': result, 'channel': channel,
                # 'data': data_data
            # }
        # elif packet_type == ResponsePacketType.hardware_i2c_read:
            # result, data_len = unpack(
                # '<HB', payload[:3]
            # )
            # data_data = bytearray(payload[3:])
            # response = {
                # 'result': result, 'data': data_data
            # }
        # elif packet_type == ResponsePacketType.hardware_i2c_write:
            # written = unpack('<B', payload[:1])[0]
            # response = {
                # 'written': written
            # }
        # elif packet_type == ResponsePacketType.test_get_channel_map:
            # # channel_map_len = unpack(
            # #    '<B', payload[:1]
            # # )[0]
            # channel_map_data = bytearray(payload[1:])
            # response = {
                # 'channel_map': channel_map_data
            # }
        # elif packet_type == ResponsePacketType.test_debug:
            # # output_len = unpack('<B',
            # #                     payload[:1])[0]
            # output_data = bytearray(payload[1:])
            # response = {
                # 'output': output_data
            # }
        elif packet_type == ResponsePacketType.gatt_discover_primary_services:
            result = unpack('<H', payload)
            response = {
                'result': result
            }
        elif packet_type == ResponsePacketType.gatt_discover_descriptors:
            result = unpack('<H', payload)
            response = {
                'result': result
            }
        elif packet_type == ResponsePacketType.gatt_discover_characteristics:
            result= unpack('<H', payload)
            response = {
                'result': result
            }


        return packet_type, response

    def _decode_event_packet(self, packet_class, packet_command, payload,
                             payload_length):
        packet_type = EVENT_PACKET_MAPPING.get((packet_class, packet_command))
        if packet_type is None:
            raise UnknownMessageType(
                "Packet class %d and command %d is not recognized" %
                (packet_class, packet_command))

        response = {}
        if packet_type == EventPacketType.system_boot:
            data = unpack('<HHHHIHI', payload[:18])
            response = {
                'major': data[0], 'minor': data[1],
                'patch': data[2], 'build': data[3],
                'bootloader': data[4], 'hw': data[5],
                'hash': data[6]
            }
        elif packet_type == EventPacketType.system_error:
            reason, data_value = unpack('<HB', payload)
            response = {
                'reason': reason,
                'data': data_value
            }
        # elif packet_type == EventPacketType.system_debug:
            # data_len = unpack('<B', payload[:1])[0]
            # data_data = bytearray(payload[1:])
            # response = {
                # 'data': data_data
            # }
        # elif packet_type in [EventPacketType.system_endpoint_watermark_rx,
                             # EventPacketType.system_endpoint_watermark_tx
                             # ]:
            # endpoint, data = unpack(
                # '<BB', payload[:2]
            # )
            # response = {
                # 'endpoint': endpoint, 'data': data
            # }
        # elif packet_type == EventPacketType.system_script_failure:
            # address, reason = unpack(
                # '<HH', payload[:4]
            # )
            # response = {
                # 'address': address, 'reason': reason
            # }
        # elif packet_type == EventPacketType.flash_ps_key:
            # key, value_len = unpack(
                # '<HB', payload[:3]
            # )
            # value_data = bytearray(payload[3:])
            # response = {
                # 'key': key, 'value': value_data
            # }
        elif packet_type == EventPacketType.gatt_server_attribute_value:
            connection, attribute, att_opcode, offset, value_len = unpack(
                '<BHBHB', payload[:7]
            )
            value_data = bytearray(payload[7:])
            response = {
                'connection_handle': connection, 'attribute_handle': attribute,
                'attribute_opcode': att_opcode, 'offset': offset,
                'value': value_data
            }
        elif packet_type == EventPacketType.gatt_server_user_read_request:
            connection, handle, att_opcode, offset = unpack(
                '<BHBH', payload[:6]
            )
            response = {
                'connection_handle': connection, 'handle': handle,
                'attribute_opcode': att_opcode, 'offset': offset
            }
        elif packet_type == EventPacketType.gatt_server_characteristic_status:
            connection, handle, flags, client_flags = unpack(
                '<BHBH', payload[:6]
            )
            response = {
                'connection_handle': connection, 'handle': handle,
                'flags': flags, 'client_flags': client_flags
            }
        elif packet_type == EventPacketType.le_connection_closed:
            reason, connection = unpack(
                '<HB', payload[:3]
            )
            response = {
                'connection_handle': connection, 'reason': reason
            }
        elif packet_type == EventPacketType.le_connection_opened:
            data = unpack('<6BBBBBB', payload[:11])
            address = data[0:6]
            response = {
                'address': address, 'address_type': data[6],
                'master': data[7],'connection_handle': data[8],
                'bonding': data[9], 'advertiser': data[10],
            }
        elif packet_type == EventPacketType.le_connection_parameters:
            data = unpack('<BHHHBH', payload[:10])
            response = {
                'connection_handle': data[0],
                'conn_interval': data[1], 'timeout': data[3],
                'latency': data[2],
                'security_mode': data[4], 'txsize': data[5],
            }
        elif packet_type == EventPacketType.le_connection_rssi:
            status, rssi = unpack(
                '<Bb', payload[:2]
            )
            response = {
                'status': status, 'rssi': rssi
            }
        elif packet_type == EventPacketType.le_connection_phy_status:
            connection, phy = unpack(
                '<BB', payload[:2]
            )
            response = {
                'connection_handle': connection, 'phy': phy
            }
        # elif packet_type == EventPacketType.connection_version_ind:
            # connection, vers_nr, comp_id, sub_vers_nr = unpack(
                # '<BBHH', payload[:6]
            # )
            # response = {
                # 'connection_handle': connection, 'vers_nr': vers_nr,
                # 'comp_id': comp_id, 'sub_vers_nr': sub_vers_nr
            # }
        # elif packet_type == EventPacketType.connection_feature_ind:
            # connection, features_len = unpack(
                # '<BB', payload[:2]
            # )
            # features_data = bytearray(payload[2:])
            # response = {
                # 'connection_handle': connection, 'features': features_data
            # }
        # elif packet_type == EventPacketType.connection_raw_rx:
            # connection, data_len = unpack(
                # '<BB', payload[:2]
            # )
            # data_data = bytearray(payload[2:])
            # response = {
                # 'connection_handle': connection, 'data': data_data
            # }
        # elif packet_type == EventPacketType.attclient_indicated:
            # connection, attrhandle = unpack(
                # '<BH', payload[:3]
            # )
            # response = {
                # 'connection_handle': connection, 'attrhandle': attrhandle
            # }
        elif packet_type == EventPacketType.attclient_procedure_completed:
            connection, result, chrhandle = unpack(
                '<BHH', payload[:5]
            )
            response = {
                'connection_handle': connection, 'result': result,
                'chrhandle': chrhandle
            }
        elif packet_type == EventPacketType.gatt_mtu_exchanged:
            connection, mtu = unpack(
                '<BH', payload[:3]
            )
            response = {
                'connection_handle': connection, 'mtu': mtu,
            }
        elif packet_type == EventPacketType.gatt_service:
            connection, service, uuid_len = unpack(
                '<BIB', payload[:6]
            )
            uuid_data = bytearray(payload[6:])
            response = {
                'connection_handle': connection,
                'service': service,
                'uuid': uuid_data
            }
        # elif packet_type == EventPacketType.attclient_attribute_found:
            # data = unpack('<BHHBB', payload[:7])
            # uuid_data = bytearray(payload[7:])
            # response = {
                # 'connection_handle': data[0], 'chrdecl': data[1],
                # 'value': data[2], 'properties': data[3],
                # 'uuid': uuid_data
            # }
        elif packet_type == EventPacketType.attclient_find_information_found:
            connection, chrhandle, uuid_len = unpack(
                '<BHB', payload[:4]
            )
            uuid_data = bytearray(payload[4:])
            response = {
                'connection_handle': connection, 'chrhandle': chrhandle,
                'uuid': uuid_data
            }
        elif packet_type == EventPacketType.attclient_attribute_value:
            connection, atthandle, type, value_len = unpack(
                '<BHBB', payload[:5]
            )
            value_data = bytearray(payload[5:])
            response = {
                'connection_handle': connection, 'atthandle': atthandle,
                'type': type, 'value': value_data
            }
        # elif packet_type == EventPacketType.attclient_read_multiple_response:
            # connection, handles_len = unpack(
                # '<BB', payload[:2]
            # )
            # handles_data = bytearray(payload[2:])
            # response = {
                # 'connection_handle': connection, 'handles': handles_data
            # }
        # elif packet_type == EventPacketType.sm_smp_data:
            # handle, packet, data_len = unpack(
                # '<BBB', payload[:3]
            # )
            # data_data = bytearray(payload[3:])
            # response = {
                # 'handle': handle, 'packet': packet,
                # 'data': data_data
            # }
        elif packet_type == EventPacketType.sm_bonding_fail:
            handle, result = unpack(
                '<BH', payload[:3]
            )
            response = {
                'handle': handle, 'result': result
            }
        elif packet_type == EventPacketType.sm_passkey_display:
            handle, passkey = unpack(
                '<BI', payload[:5]
            )
            response = {
                'handle': handle, 'passkey': passkey
            }
        elif packet_type == EventPacketType.sm_passkey_request:
            handle = unpack('<B', payload[:1])[0]
            response = {
                'handle': handle
            }
        elif packet_type == EventPacketType.sm_bond_status:
            bond, keysize, mitm, keys = unpack(
                '<BBBB', payload[:4]
            )
            response = {
                'bond': bond, 'keysize': keysize, 'mitm': mitm,
                'keys': keys
            }
        elif packet_type == EventPacketType.le_gap_scan_response:
            data = unpack('<bB6BBBB', payload[:11])
            sender = bytearray(data[2:8])
            data_data = bytearray(payload[11:])
            response = {
                'rssi': data[0], 'packet_type': data[1],
                'sender': sender, 'address_type': data[9],
                'bond': data[10], 'data': data_data
            }
        # elif packet_type == EventPacketType.gap_mode_changed:
            # discover, connect = unpack(
                # '<BB', payload[:2]
            # )
            # response = {
                # 'discover': discover, 'connect': connect
            # }
        # elif packet_type == EventPacketType.hardware_io_port_status:
            # timestamp, port, irq, state = unpack(
                # '<IBBB', payload[:7]
            # )
            # response = {
                # 'timestamp': timestamp, 'port': port, 'irq': irq,
                # 'state': state
            # }
        elif packet_type == EventPacketType.hardware_soft_timer:
            handle = unpack('<B', payload[:1])[0]
            response = {
                'handle': handle
            }
        # elif packet_type == EventPacketType.hardware_adc_result:
            # input, value = unpack('<Bh', payload[:3])
            # response = {
                # 'input': input, 'value': value
            # }
        elif packet_type == EventPacketType.gatt_characteristic:  # 9, 2

            connection, characteristic, properties = unpack('<BHB', payload[:4])
            uuid = bytearray(payload[5:])
            response = {
                'connection_handle': connection,
                'characteristic': characteristic,
                'properties': properties,
                'uuid': uuid
            }

        elif packet_type == EventPacketType.gatt_descriptor:  # 9, 3

            connection, descriptor = unpack('<BH', payload[:3])
            uuid = bytearray(payload[4:])
            response = {
                'connection_handle': connection,
                'descriptor': descriptor,
                'uuid' : uuid
            }

        elif packet_type == EventPacketType.gatt_characteristic_value:  # 9, 4

            # TODO: TEST
            connection, characteristic, att_opcode, offset = unpack('<BHBH', payload[:6])
            value = bytearray(payload[7:])
            response = {
                'connection_handle': connection,
                'characteristic': characteristic,
                'att_opcode' : att_opcode,
                'offset': offset,
                'value': value
            }

        elif packet_type == EventPacketType.gatt_descriptor_value:  # 9, 5

            # TODO: TEST
            connection, descriptor, offset = unpack('<BHH', payload[:5])
            value = bytearray(payload[6:])
            response = {
                'connection_handle': connection,
                'descriptor': descriptor,
                'offset': offset,
                'value': value
            }

        elif packet_type == EventPacketType.gatt_procedure_completed: # 9, 6

            connection, result = unpack('<BH', payload)
            response = {
                'connection_handle': connection,
                'result': result
            }

        return packet_type, response

    def decode_packet(self, packet):
        """
        Decode the packet and call the appropriate handler for the packet type.

        packet -- a list of bytes in the packet to decode.

        Raises an UnknownMessageType if the message could not be decoded.

        Returns a tuple of (PacketType, dict response data)

          BGAPI packet structure:
            Byte 0:
                  [7] - 1 bit, Message Type (MT)     Command/Response, 1 = Event
                [6:3] - 4 bits, Technology Type (TT)    0100 = BLEv2
                [2:0] - 3 bits, Length High (LH)      Payload length (high bits)
            Byte 1:     8 bits, Length Low (LL)        Payload length (low bits)
            Byte 2:     8 bits, Class ID (CID)          Command class ID
            Byte 3:     8 bits, Command ID (CMD)         Command ID
            Bytes 4-n:  0 - 2048 Bytes, Payload (PL) Up to 2048 bytes of payload
        """
        packet_id, payload_length, packet_class, packet_command = packet[:4]
        # TODO we are not parsing out the high bits of the payload length from
        # the first byte
        payload = bytearray(packet[4:])
        message_type = packet_id & 0x88
        if message_type == 0:
            return self._decode_response_packet(
                packet_class, packet_command, payload, payload_length)
        elif message_type == 0x80:
            return self._decode_event_packet(
                packet_class, packet_command, payload, payload_length)

        raise UnknownMessageType(
            "The message type '%d' is not recognized as the request or "
            "response type, and cannot be decoded" % message_type)
