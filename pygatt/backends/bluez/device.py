import functools
import logging
import time

from gi.repository import GLib
from pygatt import BLEDevice
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from pygatt.exceptions import NotConnectedError

log = logging.getLogger(__name__)


def connection_required(func):
    """Raise an exception before calling the actual function if the device is
    not connection.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self._connected:
            raise NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class BluezBLEDevice(BLEDevice):
    """A BLE device connection initiated by the Bluez (DBUS) backend.
    """
    def __init__(self, address, dbus_path, dbus_helper):
        super(BluezBLEDevice, self).__init__(address)
        self._dbus_path = dbus_path
        self._dbus = dbus_helper
        self._connected = False
        self._subscribed_characteristics = {}

    def subscribe(self, uuid, callback=None, indication=False):
        if uuid in self._subscribed_characteristics:
            self._subscribed_characteristics[uuid].add(callback)
            return

        objs = self._dbus.objects_by_property({'UUID': uuid},
                interface=self._dbus.GATT_CHAR_INTERFACE)
        log.debug("Subscribing to %s (%d objs)", uuid, len(objs))

        for o in objs:
            log.debug(".. on service: %s", o[self._dbus.GATT_CHAR_INTERFACE].Service)
            o[self._dbus.DBUS_PROPERTIES_INTERFACE].PropertiesChanged.connect(
                    functools.partial(self.properties_changed,
                                      service=o.Service, uuid=uuid))
            el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
            self._subscribed_characteristics[uuid] = set((callback,))
            el_gatt_o.StartNotify()

    def unsubscribe(self, uuid):
        if uuid not in self._subscribed_characteristics:
            return

        objs = self._dbus.objects_by_property({'UUID': uuid},
                interface=self._dbus.GATT_CHAR_INTERFACE)
        for o in objs:
            el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
            if el_gatt_o.Notifying:
                el_gatt_o.StopNotify()
            del(self._subscribed_characteristics[uuid])

    def properties_changed(self, interface, changed, invalidated,
                           service=None, uuid=None):
        log.debug("Property changed on service: %s, uuid %s", service, uuid)
        if uuid is not None and uuid in self._subscribed_characteristics:
            for cb in self._subscribed_characteristics[uuid]:
                cb(interface, changed, invalidated, service=service, uuid=uuid)
        elif uuid is not None:
            log.error("No subscription for UUID {}".format(uuid))

    def _notification_handles(self, uuid):
        uuid_parts = uuid.split('-')
        uuid_parts[0] = ('%08d' % (int(uuid_parts[0]) + 1))
        uuid_notification = '-'.join(uuid_parts)
        return uuid, uuid_notification

    def get_handle(self, char_uuid):
        log.warning('get_handle not implemented - returning given uuid')
        return char_uuid

    @connection_required
    def bond(self, *args, **kwargs):
        raise NotImplementedError()

    @connection_required
    def clear_bond(self, address=None):
        raise NotImplementedError()

    @connection_required
    def char_read(self, uuid, *args, **kwargs):
        """
        Reads a Characteristic by uuid.
        :param bledevice: BluezBLEDevice instance
        :param uuid: UUID of Characteristic to read.
        :type uuid: str
        :return: bytearray of result.
        :rtype: bytearray
        """
        log.debug("Char read from %s", uuid)
        objects = self._dbus.get_managed_objects()
        for path, ifaces in objects.items():
            iface = ifaces.get(self._dbus.GATT_CHAR_INTERFACE)
            if iface is None or iface['UUID'] != uuid:
                # if iface is not None: print(iface['UUID'])
                continue
            dbus_obj = self._dbus.object_by_path(path,
                    interface=self._dbus.GATT_CHAR_INTERFACE)
            v = dbus_obj.ReadValue({})
            return bytearray(v)
        raise Exception("UUID {} not found".format(uuid))

    @connection_required
    def char_write(self, uuid, value, wait_for_response=False):
        objs = self._dbus.objects_by_property({'UUID': uuid},
                                                      base_path='/')
        for o in objs:
            log.debug("Writing to %s", o.Service)
            el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
            el_gatt_o.WriteValue(value, {})

    @connection_required
    def char_write_handle(self, handle, *args, **kwargs):
        raise NotImplementedError()

    @property
    def services_resolved(self):
        dbus_dev_obj = self._dbus.object_by_path(self._dbus_path,
                interface=self._dbus.DEVICE_INTERFACE)
        return bool(dbus_dev_obj.ServicesResolved)

    @property
    def connected(self):
        return self._connected

    def connect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        """ Connect to this BLE device

        timeout -- Timeout in seconds to attempt a connection
        """
        if self._connected:
            return

        log.info("Connecting to %s", self.address)
        timeout_time = time.time() + timeout
        while True:
            try:
                bus_obj = self._dbus.get(self._dbus.SERVICE_NAME,
                                         self._dbus_path,
                                         timeout=timeout)
                bus_obj.Connect()
                break

            except GLib.Error as e:
                # TODO remove print
                print((e.code, e.message))
                log.error("Error connecting to %s: %d %s",
                          self.address, e.code, e.message)
                sleep = 0.1
                if e.code == 24:  # Timeout was reached
                    sleep = 2
                elif e.code == 36:  # Operation already in progress,
                                    # Software caused connection abort
                    pass

                if time.time() + sleep >= timeout_time:
                    raise NotConnectedError(
                            "Connection to {} timed out".format(self.address))

                time.sleep(sleep)

        self._connected = True

        if not self.services_resolved:
            log.info("Services not (all) resolved yet, " +
                     "discovery continues in the background")

    def disconnect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        for o in self._subscribed_characteristics.keys():
            self.unsubscribe(o)

        bus_obj = self._dbus.get(self._dbus.SERVICE_NAME, self._dbus_path,
                                 timeout=timeout)
        bus_obj.Disconnect()
        self._connected = False
        log.info("Disconnected from %s", self.address)

    def discover_characteristics(self, bledevice,
                                 timeout=DEFAULT_CONNECT_TIMEOUT_S):
        dbus_obj = self._dbus.object_by_path(self._dbus_path,
                                            interface=self.DEVICE_INTERFACE)

        log.debug("Service discovery not finished before timeout")
        while not dbus_obj.ServicesResolved:
            if time.time() >= timeout:
                break
            time.sleep(0.1)

        if not dbus_obj.ServicesResolved:
            log.warn("Service discovery not finished after timeout")

        characteristics = dbus_obj.UUIDs

        # A generic object with a None handle, to match the interface
        class obj(object):
            def handle(self):
                return None

        o = obj()
        self._characteristics = dict(zip(characteristics,
            [o for i in range(len(characteristics))]))
        return self._characteristics

    def get_rssi(self):
        try:
            return self._dbus.object_by_path(self._dbus_path).RSSI
        except:
            log.info("Failed to get RSSI for device {}".format(
                    self.address))
            return float('nan')
