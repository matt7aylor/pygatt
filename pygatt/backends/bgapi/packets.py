from struct import pack


class BGAPICommandPacketBuilder(object):
    @staticmethod
    def system_reset(boot_in_dfu):
        return pack('<4BB', 0x20, 1, 1, 1, boot_in_dfu)

    @staticmethod
    def system_hello():
        return pack('<4B', 0x20, 0, 1, 0)

    @staticmethod
    def system_get_bt_address():
        return pack('<4B', 0x20, 0, 1, 3)

    # Not present?
    #  @staticmethod
    # def system_reg_write(address, value):
        # return pack('<4BHB', 0, 3, 0, 3, address, value)

    # Not present?
    # @staticmethod
    # def system_reg_read(address):
        # return pack('<4BH', 0, 2, 0, 4, address)

    @staticmethod
    def system_get_counters(reset=0):
        return pack('<5B', 0x20, 1, 1, 0x0f, reset)  # XXX New form, needs checking

    # @staticmethod
    # def system_get_connections():
        # return pack('<4B', 0, 0, 0, 6)

    # @staticmethod
    # def system_read_memory(address, length):
        # return pack('<4BIB', 0, 5, 0, 7, address, length)

    # @staticmethod
    # def system_get_info():
        # return pack('<4B', 0, 0, 0, 8)

    # @staticmethod
    # def system_endpoint_tx(endpoint, data):
        # return pack('<4BBB%dB' % len(data), 0, 2 + len(data), 0, 9,
                    # endpoint, len(data), *data)

    # @staticmethod
    # def system_whitelist_append(address, address_type):
        # return pack('<4B6BB', 0, 7, 0, 10,
                    # address[0],
                    # address[1],
                    # address[2],
                    # address[3],
                    # address[4],
                    # address[5],
                    # address_type)

    # @staticmethod
    # def system_whitelist_remove(address, address_type):
        # return pack('<4B6BB', 0, 7, 0, 11,
                    # address[0],
                    # address[1],
                    # address[2],
                    # address[3],
                    # address[4],
                    # address[5],
                    # address_type)

    # @staticmethod
    # def system_whitelist_clear():
        # return pack('<4B', 0, 0, 0, 12)

    # @staticmethod
    # def system_endpoint_rx(endpoint, size):
        # return pack('<4BBB', 0, 2, 0, 13, endpoint, size)

    # @staticmethod
    # def system_endpoint_set_watermarks(endpoint, rx, tx):
        # return pack('<4BBBB', 0, 3, 0, 14, endpoint, rx, tx)

    # @staticmethod
    # def flash_ps_defrag():
        # return pack('<4B', 0, 0, 1, 0)

    # @staticmethod
    # def flash_ps_dump():
        # return pack('<4B', 0, 0, 1, 1)

    @staticmethod
    def flash_ps_erase_all():
        return pack('<4B', 0x20, 0, 0x0d, 1)

    @staticmethod
    def flash_ps_save(key, value):
        return pack('<4BHB%dB' % len(value), 0x20, 3 + len(value), 0x0d, 2,
                    key, len(value), *value)

    @staticmethod
    def flash_ps_load(key):
        return pack('<4BH', 0x20, 2, 0x0d, 3, key)

    @staticmethod
    def flash_ps_erase(key):
        return pack('<4BH', 0x20, 2, 0x0d, 4, key)

    # @staticmethod
    # def flash_erase_page(page):
        # return pack('<4BB', 0, 1, 1, 6, page)

    # @staticmethod
    # def flash_write_words(address, words):
        # return pack('<4BHB%dB' % len(words), 0, 3 + len(words), 1, 7,
                    # address, len(words), *words)

    @staticmethod
    def attributes_write(handle, offset, value):
        return pack('<4BHBB%dB' % len(value), 0, 4 + len(value), 2, 0,
                    handle, offset, len(value), *value)

    @staticmethod
    def attributes_read(handle, offset):
        return pack('<4BHH', 0, 4, 2, 1, handle, offset)

    @staticmethod
    def attributes_read_type(handle):
        return pack('<4BH', 0, 2, 2, 2, handle)

    @staticmethod
    def attributes_user_read_response(connection, att_error, value):
        return pack('<4BBBB%dB' % len(value), 0, 3 + len(value), 2, 3,
                    connection, att_error, len(value), *value)

    @staticmethod
    def attributes_user_write_response(connection, att_error):
        return pack('<4BBB', 0, 2, 2, 4, connection, att_error)

    @staticmethod
    def le_connection_close(connection):
        return pack('<4BB', 0x20, 1, 0x08, 0x04, connection)

    @staticmethod
    def connection_get_rssi(connection):
        return pack('<4BB', 0, 1, 3, 1, connection)

    @staticmethod
    def connection_update(connection, interval_min, interval_max,
                          latency, timeout):
        return pack('<4BBHHHH', 0, 9, 3, 2, connection, interval_min,
                    interval_max, latency, timeout)

    @staticmethod
    def connection_version_update(connection):
        return pack('<4BB', 0, 1, 3, 3, connection)

    @staticmethod
    def connection_channel_map_get(connection):
        return pack('<4BB', 0, 1, 3, 4, connection)

    @staticmethod
    def connection_channel_map_set(connection, channel_map):
        return pack('<4BBB%dB' % len(channel_map), 0, 2 +
                    len(channel_map), 3, 5,
                    connection, len(channel_map), *channel_map)

    @staticmethod
    def connection_features_get(connection):
        return pack('<4BB', 0, 1, 3, 6, connection)

    @staticmethod
    def connection_get_status(connection):
        return pack('<4BB', 0, 1, 3, 7, connection)

    @staticmethod
    def connection_raw_tx(connection, data):
        return pack('<4BBB%dB' % len(data), 0, 2 + len(data), 3, 8,
                    connection, len(data), *data)

    # @staticmethod
    # def attclient_find_by_type_value(connection, start, end, uuid, value):
        # return pack('<4BBHHHB%dB' % len(value), 0, 8 + len(value), 4, 0,
                    # connection, start, end, uuid, len(value), *value)

    # @staticmethod
    # def attclient_read_by_group_type(connection, start, end, uuid):
        # return pack('<4BBHHB%dB' % len(uuid), 0, 6 + len(uuid), 4, 1,
                    # connection, start, end, len(uuid), *uuid)

    # @staticmethod
    # def attclient_read_by_type(connection, start, end, uuid=[0x03, 0x28]):
        # # Using the default UUID type to find custom UUIDs, which seems to make
        # # querying for characteristics faster.
        # return pack('<4BBHHB%dB' % len(uuid), 0, 6 + len(uuid), 4, 2,
                    # connection, start, end, len(uuid), *uuid)

    @staticmethod
    def attclient_find_information(connection, start, end):
        return pack('<4BBHH', 0, 5, 4, 3, connection, start, end)

    @staticmethod
    def attclient_read_by_handle(connection, chrhandle):
        return pack('<4BBH', 0, 3, 4, 4, connection, chrhandle)

    @staticmethod
    def attclient_attribute_write(connection, atthandle, data):
        return pack('<4BBHB%dB' % len(data), 0, 4 + len(data), 4, 5,
                    connection, atthandle, len(data), *data)

    @staticmethod
    def attclient_write_command(connection, atthandle, data):
        return pack('<4BBHB%dB' % len(data), 0, 4 + len(data), 4, 6,
                    connection, atthandle, len(data), *data)

    # @staticmethod
    # def attclient_indicate_confirm(connection):
        # return pack('<4BB', 0, 1, 4, 7, connection)

    @staticmethod
    def attclient_read_long(connection, chrhandle):
        return pack('<4BBH', 0, 3, 4, 8, connection, chrhandle)

    @staticmethod
    def attclient_prepare_write(connection, atthandle, offset, data):
        return pack('<4BBHHB%dB' % len(data), 0, 6 + len(data), 4, 9,
                    connection, atthandle, offset, len(data),
                    *data)

    @staticmethod
    def attclient_execute_write(connection, commit):
        return pack('<4BBB', 0, 2, 4, 10, connection, commit)

    # @staticmethod
    # def attclient_read_multiple(connection, handles):
        # return pack('<4BBB%dB' % len(handles), 0,
                    # 2 + len(handles), 4,
                    # 11, connection, len(handles),
                    # *handles)

    @staticmethod
    def sm_encrypt_start(handle, bonding):
        return pack('<4BBB', 0, 2, 5, 0, handle, bonding)

    @staticmethod
    def sm_set_bondable_mode(bondable):
        return pack('<4BB', 0x20, 1, 0x0f, 0, bondable)

    @staticmethod
    def sm_delete_bonding(handle):
        return pack('<4BB', 0, 1, 5, 2, handle)

    @staticmethod
    def sm_set_parameters(mitm, min_key_size, io_capabilities):
        return pack('<4BBBB', 0, 3, 5, 3, mitm, min_key_size, io_capabilities)

    @staticmethod
    def sm_passkey_entry(handle, passkey):
        return pack('<4BBI', 0, 5, 5, 4, handle, passkey)

    @staticmethod
    def sm_get_bonds():
        return pack('<4B', 0, 0, 5, 5)

    @staticmethod
    def sm_set_oob_data(oob):
        return pack('<4BB%dB' % len(oob), 0, 1 + len(oob), 5, 6,
                    len(oob), *oob)

    @staticmethod
    def gap_set_privacy_flags(peripheral_privacy, central_privacy):
        return pack('<4BBB', 0, 2, 6, 0, peripheral_privacy, central_privacy)

    @staticmethod
    def le_gap_set_mode(discover, connect):  # Deprecated XXX
        return pack('<4BBB', 0x20, 0x02, 0x03, 0x01, discover, connect)

    @staticmethod
    def le_gap_discover(mode):
        return pack('<4BB', 0x20, 1, 3, 2, mode)

    @staticmethod
    def le_gap_connect(address, addr_type, phy):
        return pack('<4B6BBB', 0x20, 8, 3, 0x1a,
                    address[-1],
                    address[-2],
                    address[-3],
                    address[-4],
                    address[-5],
                    address[-6],
                    addr_type,
                    phy)

    @staticmethod
    def le_gap_end_procedure():
        return pack('<4B', 0x20, 0, 3, 3)

    @staticmethod
    def gap_connect_selective(conn_interval_min, conn_interval_max,
                              timeout, latency):
        return pack('<4BHHHH', 0, 8, 6, 5, conn_interval_min, conn_interval_max,
                    timeout, latency)

    @staticmethod
    def gap_set_filtering(scan_policy, adv_policy, scan_duplicate_filtering):
        return pack('<4BBBB', 0, 3, 6, 6, scan_policy, adv_policy,
                    scan_duplicate_filtering)

    @staticmethod
    def le_gap_set_scan_parameters(scan_interval, scan_window, active):
        return pack('<4BHHB', 0x20, 5, 3, 6, scan_interval, scan_window, active)

    @staticmethod
    def gap_set_adv_parameters(adv_interval_min, adv_interval_max,
                               adv_channels):
        return pack('<4BHHB', 0, 5, 6, 8, adv_interval_min, adv_interval_max,
                    adv_channels)

    @staticmethod
    def gap_set_adv_data(set_scanrsp, adv_data):
        return pack('<4BBB%dB' % len(adv_data), 0, 2 + len(adv_data), 6,
                    9, set_scanrsp, len(adv_data), *adv_data)

    @staticmethod
    def gap_set_directed_connectable_mode(address, addr_type):
        return pack('<4B6BB', 0, 7, 6, 10,
                    address[0],
                    address[1],
                    address[2],
                    address[3],
                    address[4],
                    address[5],
                    addr_type)

    # @staticmethod
    # def hardware_io_port_config_irq(port, enable_bits, falling_edge):
        # return pack('<4BBBB', 0, 3, 7, 0, port, enable_bits, falling_edge)

    # @staticmethod
    # def hardware_set_soft_timer(time, handle, single_shot):
        # return pack('<4BIBB', 0, 6, 7, 1, time, handle, single_shot)

    # @staticmethod
    # def hardware_adc_read(input, decimation, reference_selection):
        # return pack('<4BBBB', 0, 3, 7, 2, input, decimation,
                    # reference_selection)

    # @staticmethod
    # def hardware_io_port_config_direction(port, direction):
        # return pack('<4BBB', 0, 2, 7, 3, port, direction)

    # @staticmethod
    # def hardware_io_port_config_function(port, function):
        # return pack('<4BBB', 0, 2, 7, 4, port, function)

    # @staticmethod
    # def hardware_io_port_config_pull(port, tristate_mask, pull_up):
        # return pack('<4BBBB', 0, 3, 7, 5, port, tristate_mask, pull_up)

    # @staticmethod
    # def hardware_io_port_write(port, mask, data):
        # return pack('<4BBBB', 0, 3, 7, 6, port, mask, data)

    # @staticmethod
    # def hardware_io_port_read(port, mask):
        # return pack('<4BBB', 0, 2, 7, 7, port, mask)

    # @staticmethod
    # def hardware_spi_config(channel, polarity, phase, bit_order,
                            # baud_e, baud_m):
        # return pack('<4BBBBBBB', 0, 6, 7, 8, channel, polarity, phase,
                    # bit_order, baud_e, baud_m)

    # @staticmethod
    # def hardware_spi_transfer(channel, data):
        # return pack('<4BBB%dB' % len(data), 0, 2 + len(data), 7, 9,
                    # channel, len(data), *data)

    # @staticmethod
    # def hardware_i2c_read(address, stop, length):
        # return pack('<4BBBB', 0, 3, 7, 10, address, stop, length)

    # @staticmethod
    # def hardware_i2c_write(address, stop, data):
        # return pack('<4BBBB%dB' % len(data), 0, 3 + len(data), 7, 11,
                    # address, stop, len(data), *data)

    # @staticmethod
    # def hardware_set_txpower(power):
        # return pack('<4BB', 0, 1, 7, 12, power)

    # @staticmethod
    # def hardware_timer_comparator(timer, channel, mode, comparator_value):
        # return pack('<4BBBBH', 0, 5, 7, 13, timer, channel, mode,
                    # comparator_value)

    # @staticmethod
    # def test_phy_tx(channel, length, type):
        # return pack('<4BBBB', 0, 3, 8, 0, channel, length, type)

    # @staticmethod
    # def test_phy_rx(channel):
        # return pack('<4BB', 0, 1, 8, 1, channel)

    # @staticmethod
    # def test_phy_end():
        # return pack('<4B', 0, 0, 8, 2)

    # @staticmethod
    # def test_phy_reset():
        # return pack('<4B', 0, 0, 8, 3)

    # @staticmethod
    # def test_get_channel_map():
        # return pack('<4B', 0, 0, 8, 4)

    # @staticmethod
    # def test_debug(data):
        # return pack('<4BB%dB' % len(data), 0, 1 + len(data), 8, 5,
                    # len(data), *data)
    @staticmethod
    def gatt_discover_primary_services(connection):
        return pack('<4BB', 0x20, 0x01, 0x09, 0x01, connection)

    @staticmethod
    def gatt_discover_characteristics(connection, service_handle):
        return pack('<4BBI', 0x20, 0x05, 0x09, 0x03, connection, service_handle)

    @staticmethod
    def gatt_discover_descriptors(connection, characteristic):
        return pack('<4BBH', 0x20, 0x03, 0x09, 0x06, connection, characteristic)

    @staticmethod
    def gatt_write_characteristic_value(connection, characteristic, characteristic_value):
        return pack('<4BBH%dB' % len(characteristic_value) , 0x20, 0x04, 0x09, 0x09, connection, characteristic, *characteristic_value)

    @staticmethod
    def gatt_read_characteristic_value(connection, characteristic):
        return pack('<4BBH', 0x20, 0x03, 0x09, 0x07, connection, characteristic)  # TODO just for marking: Tried to get data from Thingy (its name), seems to be working.




    @staticmethod
    def gatt_discover_characteristics_by_uuid(connection, service_handle, uuid): # TODO
        return pack('<4BBH', 0x20, 0x06, 0x09, 0x06, connection, service_handle, uuid)

    @staticmethod
    def gatt_discover_primary_services_by_uuid(connection, uuid): # TODOs
        return pack('<4BB%dB' % len(uuid), 0x20, 0x02, 0x09, 0x02, connection, uuid) # TODO is this right?

    @staticmethod
    def gatt_execute_characteristic_value_write(connection, flags):  # TODO
        return pack('<4BB', 0x20, 0x02, 0x09, 0x0c, connection, flags)

    @staticmethod
    def gatt_find_included_services(connection, service): # TODO
        return pack('<4BBI', 0x20, 0x05, 0x09, 0x10, connection, service)



    @staticmethod
    def gatt_read_characteristic_value_by_uuid(connection, service_handle, characteristic):
        return pack('<4BBI%dB' % len(characteristic), 0x20, 0x06, 0x09, 0x08, connection, service_handle, characteristic) # TODO