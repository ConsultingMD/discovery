# -*- coding: utf-8 -*-
import datetime
import logging
import pytz
import query
import socket

from flask import current_app as app
from flask import request

from ..stats import get_stats
from .. import settings


class ListenerService():
    """Provides methods for querying for listeners"""

    def __init__(self, query_backend=query.DynamoQueryBackend()):
        """
        Initialize ListenerService against a given query backend.

        :param query_backend: provides access to a storage engine for the listeners.
        :type query_backend: query.QueryBackend
        """
        self.query_backend = query_backend

    def list(self):
        """Returns a json list of listeners.

        :returns: all of the listeners
        :rtype: list(dict)
        """
        cached_listeners = app.cache.get('_listeners')
        if cached_listeners:
            return cached_listeners

        listeners = self.query_backend.get_listeners()
        if listeners is None:
            listeners = []

        app.cache.set('_listeners', listeners, settings.value.CACHE_TTL)
        return listeners

    def update(self, name, address, filters, ssl_context, bind_to_port, use_proxy_proto, use_original_dst, per_connection_buffer_limit_bytes, drain_type):
        """Updates the listener registration entry for one host.

        :param name: the listener to update
        :param address: the address of the host, e.g. "tcp://127.0.0.1:80"
        :param filters: a list of individual network filters that make up the filter chain for connections established with the listener
        :param ssl_context: the TLS context configuration for a TLS listener. If no TLS context block is defined, the listener is a plain text listener.
        :param bind_to_port: whether or not the listener should bind to the port
        :param use_proxy_proto: whether the listener should expect a PROXY protocol V1 header on new connections
        :param use_original_dst: If a connection is redirected using iptables, the port on which the proxy receives it 
            might be different from the original destination address. When this flag is set to true, the listener hands 
            off redirected connections to the listener associated with the original destination address. If there is no 
            listener associated with the original destination address, the connection is handled by the listener that 
            receives it
        :param per_connection_buffer_limit_bytes: soft limit on size of the listener’s new connection read and write buffers
        :param drain_type: the type of draining that the listener does. allowed values include default and modify_only.

        :type name: str
        :type address: str
        :type filters: list
        :type ssl_context: dict
        :type bind_to_port: bool
        :type use_proxy_proto: bool
        :type use_original_dst: bool
        :type per_connection_buffer_limit_bytes: int
        :type drain_type: str

        :returns: True on success, False on failure
        :rtype: bool
        """

        if not address:
            logging.error("Update: Missing required parameter - address. url=%s params=%s")
            return False

        if not filters:
            logging.error("Update: Missing required parameter - filters")
            return False

        try:
            bind_to_port = bool(bind_to_port)
        except ValueError:
            logging.error("Update: Invalid bind_to_port")
            return False

        try:
            use_proxy_proto = bool(use_proxy_proto)
        except ValueError:
            logging.error("Update: Invalid use_proxy_proto")
            return False

        try:
            use_original_dst = bool(use_original_dst)
        except ValueError:
            logging.error("Update: Invalid use_original_dst")
            return False

        self._create_or_update_listener(name, address, filters, ssl_context, bind_to_port, use_proxy_proto, use_original_dst, per_connection_buffer_limit_bytes, drain_type)
        return True

    def delete(self, address):
        """Attempts to delete the listener with the given address.

        :param address: the address of the listener to delete

        :type address: str

        :returns: True if delete successful, False otherwise
        :rtype: bool
        """

        if not address:
            logging.error("Delete: Missing required parameter - address")
            return False

        return self.query_backend.delete_listener(address)

    def _create_or_update_listener(self, name, address, filters, ssl_context, bind_to_port, use_proxy_proto, use_original_dst, per_connection_buffer_limit_bytes, drain_type):
        """
        Create a new listener entry or update an existing entry.

        :param name: the listener to update
        :param address: the address of the host, e.g. "tcp://127.0.0.1:80"
        :param filters: a list of individual network filters that make up the filter chain for connections established with the listener
        :param ssl_context: the TLS context configuration for a TLS listener. If no TLS context block is defined, the listener is a plain text listener.
        :param bind_to_port: whether or not the listener should bind to the port
        :param use_proxy_proto: whether the listener should expect a PROXY protocol V1 header on new connections
        :param use_original_dst: If a connection is redirected using iptables, the port on which the proxy receives it 
            might be different from the original destination address. When this flag is set to true, the listener hands 
            off redirected connections to the listener associated with the original destination address. If there is no 
            listener associated with the original destination address, the connection is handled by the listener that 
            receives it
        :param per_connection_buffer_limit_bytes: soft limit on size of the listener’s new connection read and write buffers
        :param drain_type: the type of draining that the listener does. Allowed values include default and modify_only.

        :type name: str
        :type address: str
        :type filters: list
        :type ssl_context: dict
        :type bind_to_port: bool
        :type use_proxy_proto: bool
        :type use_original_dst: bool
        :type per_connection_buffer_limit_bytes: int
        :type drain_type: str

        :returns: True on success, False on failure
        :rtype: bool
        """
        listener = self.query_backend.get_listener(address)
        if listener is None:
            listener = {
                'name': name,
                'address': address,
                'filters': filters,
                'ssl_context': ssl_context,
                'bind_to_port': bind_to_port,
                'use_proxy_proto': use_proxy_proto,
                'use_original_dst': use_original_dst,
                'per_connection_buffer_limit_bytes': per_connection_buffer_limit_bytes,
                'drain_type': drain_type
            }
        else:
            listener['name'] = name
            listener['address'] = address
            listener['filters'] = filters
            listener['ssl_context'] = ssl_context
            listener['bind_to_port'] = bind_to_port
            listener['use_proxy_proto'] = use_proxy_proto
            listener['use_original_dst'] = use_original_dst
            listener['per_connection_buffer_limit_bytes'] = per_connection_buffer_limit_bytes
            listener['drain_type'] = drain_type
        return self.query_backend.put_listener(listener)
