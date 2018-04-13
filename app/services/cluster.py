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


class ClusterService():
    """Provides methods for querying for clusters"""

    def __init__(self, query_backend=query.DynamoQueryBackend()):
        """
        Initialize ClusterService against a given query backend.

        :param query_backend: provides access to a storage engine for the clusters.
        :type query_backend: query.QueryBackend
        """
        self.query_backend = query_backend

    def list(self):
        """Returns a json list of clusters.

        :returns: all of the clusters
        :rtype: list(dict)
        """
        cached_clusters = app.cache.get('_clusters')
        if cached_clusters:
            return cached_clusters

        clusters = self.query_backend.get_clusters()
        if clusters is None:
            clusters = []

        app.cache.set('_clusters', clusters, settings.value.CACHE_TTL)
        return clusters

    def update(self, name, sd_type, connect_timeout_ms, per_connection_buffer_limit_bytes, lb_type, ring_hash_lb_config, hosts, service_name, health_check, max_requests_per_connection, circuit_breakers, ssl_context, features, http2_settings, cleanup_interval_ms, dns_refresh_rate_ms, dns_lookup_family, dns_resolvers, outlier_detection):
        """Updates the listener registration entry for one host.

        :param name: the cluster to update
        :param sd_type: the service discovery type to use for resolving the cluster. Possible options are static, strict_dns, logical_dns, *original_dst*, and sds.
        :param connect_timeout_ms: the timeout for new network connections to hosts in the cluster specified in milliseconds.
        :param per_connection_buffer_limit_bytes: soft limit on size of the cluster’s connections read and write buffers. If unspecified, an implementation defined default is applied (1MiB).
        :param lb_type: the load balancer type to use when picking a host in the cluster. Possible options are round_robin, least_request, ring_hash, random, and original_dst_lb. Note that *original_dst_lb* must be used with clusters of type *original_dst*, and may not be used with any other cluster type.
        :param ring_hash_lb_config: optional configuration for the ring hash load balancer, used when lb_type is set to ring_hash.
        :param hosts: if the service discovery type is static, strict_dns, or logical_dns the hosts array is required. Hosts array is not allowed with cluster type original_dst. How it is specified depends on the type of service discovery.
        :param service_name: this parameter is required if the service discovery type is sds. It will be passed to the SDS API when fetching cluster members.
        :param health_check: optional active health checking configuration for the cluster. If no configuration is specified no health checking will be done and all cluster members will be considered healthy at all times.
        :param max_requests_per_connection: optional maximum requests for a single upstream connection. This parameter is respected by both the HTTP/1.1 and HTTP/2 connection pool implementations. If not specified, there is no limit. Setting this parameter to 1 will effectively disable keep alive.
        :param circuit_breakers: optional circuit breaking settings for the cluster.
        :param ssl_context: the TLS configuration for connections to the upstream cluster. If no TLS configuration is specified, TLS will not be used for new connections.
        :param features: a comma delimited list of features that the upstream cluster supports. The currently supported features are http2.
        :param http2_settings: additional HTTP/2 settings that are passed directly to the HTTP/2 codec when initiating HTTP connection pool connections. These are the same options supported in the HTTP connection manager http2_settings option.
        :param cleanup_interval_ms: the interval for removing stale hosts from an original_dst cluster. Hosts are considered stale if they have not been used as upstream destinations during this interval. New hosts are added to original destination clusters on demand as new connections are redirected to Envoy, causing the number of hosts in the cluster to grow over time. Hosts that are not stale (they are actively used as destinations) are kept in the cluster, which allows connections to them remain open, saving the latency that would otherwise be spent on opening new connections. If this setting is not specified, the value defaults to 5000. For cluster types other than original_dst this setting is ignored.
        :param dns_refresh_rate_ms: if the dns refresh rate is specified and the cluster type is either strict_dns, or logical_dns, this value is used as the cluster’s dns refresh rate. If this setting is not specified, the value defaults to 5000. For cluster types other than strict_dns and logical_dns this setting is ignored.
        :param dns_lookup_family: the DNS IP address resolution policy. The options are v4_only, v6_only, and auto. If this setting is not specified, the value defaults to v4_only. When v4_only is selected, the DNS resolver will only perform a lookup for addresses in the IPv4 family. If v6_only is selected, the DNS resolver will only perform a lookup for addresses in the IPv6 family. If auto is specified, the DNS resolver will first perform a lookup for addresses in the IPv6 family and fallback to a lookup for addresses in the IPv4 family. For cluster types other than strict_dns and logical_dns, this setting is ignored.
i       :param dns_resolvers: if DNS resolvers are specified and the cluster type is either strict_dns, or logical_dns, this value is used to specify the cluster’s dns resolvers. If this setting is not specified, the value defaults to the default resolver, which uses /etc/resolv.conf for configuration. For cluster types other than strict_dns and logical_dns this setting is ignored.
        :param outlier_detection: if specified, outlier detection will be enabled for this upstream cluster. See the architecture overview for more information on outlier detection.

        :type name: str
        :type sd_type: str
        :type connect_timeout_ms: int
        :type per_connection_buffer_limit_bytes: int
        :type lb_type: str
        :type ring_hash_lb_config: dict
        :type hosts: list
        :type service_name: str
        :type health_check: dict
        :type max_requests_per_connection: int
        :type circuit_breakers: dict
        :type ssl_context: dict
        :type features: str
        :type http2_settings: dict
        :type cleanup_interval_ms: int
        :type dns_refresh_rate_ms: int
        :type dns_lookup_family: str
        :type dns_resolvers: list
        :type outlier_detection: dict

        :returns: True on success, False on failure
        :rtype: bool
        """

        if not name:
            logging.error("Update: Missing required parameter - name.")
            return False

        if not sd_type:
            logging.error("Update: Missing required parameter - sd_type.")
            return False

        if not connect_timeout_ms:
            logging.error("Update: Missing required parameter - connect_timeout_ms.")
            return False

        if not lb_type:
            logging.error("Update: Missing required parameter - lb_type.")
            return False

        try:
            connect_timeout_ms = int(connect_timeout_ms)
        except ValueError:
            logging.error("Update: Invalid connect_timeout_ms")
            return False

        self._create_or_update_cluster(name, sd_type, connect_timeout_ms, per_connection_buffer_limit_bytes, lb_type, ring_hash_lb_config, hosts, service_name, health_check, max_requests_per_connection, circuit_breakers, ssl_context, features, http2_settings, cleanup_interval_ms, dns_refresh_rate_ms, dns_lookup_family, dns_resolvers, outlier_detection)
        return True

    def delete(self, name):
        """Attempts to delete the cluster with the given name.

        :param name: the name of the cluster to delete

        :type name: str

        :returns: True if delete successful, False otherwise
        :rtype: bool
        """

        if not name:
            logging.error("Delete: Missing required parameter - name")
            return False

        return self.query_backend.delete_cluster(name)

    def _create_or_update_cluster(self, name, sd_type, connect_timeout_ms, per_connection_buffer_limit_bytes, lb_type, ring_hash_lb_config, hosts, service_name, health_check, max_requests_per_connection, circuit_breakers, ssl_context, features, http2_settings, cleanup_interval_ms, dns_refresh_rate_ms, dns_lookup_family, dns_resolvers, outlier_detection):
        """
        Create a new cluster entry or update an existing entry.

        :param name: the cluster to update
        :param sd_type: the service discovery type to use for resolving the cluster. Possible options are static, strict_dns, logical_dns, *original_dst*, and sds.
        :param connect_timeout_ms: the timeout for new network connections to hosts in the cluster specified in milliseconds.
        :param per_connection_buffer_limit_bytes: soft limit on size of the cluster’s connections read and write buffers. If unspecified, an implementation defined default is applied (1MiB).
        :param lb_type: the load balancer type to use when picking a host in the cluster. Possible options are round_robin, least_request, ring_hash, random, and original_dst_lb. Note that *original_dst_lb* must be used with clusters of type *original_dst*, and may not be used with any other cluster type.
        :param ring_hash_lb_config: optional configuration for the ring hash load balancer, used when lb_type is set to ring_hash.
        :param hosts: if the service discovery type is static, strict_dns, or logical_dns the hosts array is required. Hosts array is not allowed with cluster type original_dst. How it is specified depends on the type of service discovery.
        :param service_name: this parameter is required if the service discovery type is sds. It will be passed to the SDS API when fetching cluster members.
        :param health_check: optional active health checking configuration for the cluster. If no configuration is specified no health checking will be done and all cluster members will be considered healthy at all times.
        :param max_requests_per_connection: optional maximum requests for a single upstream connection. This parameter is respected by both the HTTP/1.1 and HTTP/2 connection pool implementations. If not specified, there is no limit. Setting this parameter to 1 will effectively disable keep alive.
        :param circuit_breakers: optional circuit breaking settings for the cluster.
        :param ssl_context: the TLS configuration for connections to the upstream cluster. If no TLS configuration is specified, TLS will not be used for new connections.
        :param features: a comma delimited list of features that the upstream cluster supports. The currently supported features are http2.
        :param http2_settings: additional HTTP/2 settings that are passed directly to the HTTP/2 codec when initiating HTTP connection pool connections. These are the same options supported in the HTTP connection manager http2_settings option.
        :param cleanup_interval_ms: the interval for removing stale hosts from an original_dst cluster. Hosts are considered stale if they have not been used as upstream destinations during this interval. New hosts are added to original destination clusters on demand as new connections are redirected to Envoy, causing the number of hosts in the cluster to grow over time. Hosts that are not stale (they are actively used as destinations) are kept in the cluster, which allows connections to them remain open, saving the latency that would otherwise be spent on opening new connections. If this setting is not specified, the value defaults to 5000. For cluster types other than original_dst this setting is ignored.
        :param dns_refresh_rate_ms: if the dns refresh rate is specified and the cluster type is either strict_dns, or logical_dns, this value is used as the cluster’s dns refresh rate. If this setting is not specified, the value defaults to 5000. For cluster types other than strict_dns and logical_dns this setting is ignored.
        :param dns_lookup_family: the DNS IP address resolution policy. The options are v4_only, v6_only, and auto. If this setting is not specified, the value defaults to v4_only. When v4_only is selected, the DNS resolver will only perform a lookup for addresses in the IPv4 family. If v6_only is selected, the DNS resolver will only perform a lookup for addresses in the IPv6 family. If auto is specified, the DNS resolver will first perform a lookup for addresses in the IPv6 family and fallback to a lookup for addresses in the IPv4 family. For cluster types other than strict_dns and logical_dns, this setting is ignored.
i       :param dns_resolvers: if DNS resolvers are specified and the cluster type is either strict_dns, or logical_dns, this value is used to specify the cluster’s dns resolvers. If this setting is not specified, the value defaults to the default resolver, which uses /etc/resolv.conf for configuration. For cluster types other than strict_dns and logical_dns this setting is ignored.
        :param outlier_detection: if specified, outlier detection will be enabled for this upstream cluster. See the architecture overview for more information on outlier detection.

        :type name: str
        :type sd_type: str
        :type connect_timeout_ms: int
        :type per_connection_buffer_limit_bytes: int
        :type lb_type: str
        :type ring_hash_lb_config: dict
        :type hosts: list
        :type service_name: str
        :type health_check: dict
        :type max_requests_per_connection: int
        :type circuit_breakers: dict
        :type ssl_context: dict
        :type features: str
        :type http2_settings: dict
        :type cleanup_interval_ms: int
        :type dns_refresh_rate_ms: int
        :type dns_lookup_family: str
        :type dns_resolvers: list
        :type outlier_detection: dict

        :returns: True on success, False on failure
        :rtype: bool
        """
        cluster = self.query_backend.get_cluster(name)
        if cluster is None:
            cluster = {
                'name': name,
                'sd_type': sd_type,
                'connect_timeout_ms': connect_timeout_ms,
                'per_connection_buffer_limit_bytes': per_connection_buffer_limit_bytes,
                'lb_type': lb_type,
                'ring_hash_lb_config': ring_hash_lb_config,
                'hosts': hosts,
                'service_name': service_name,
                'health_check': health_check,
                'max_requests_per_connection': max_requests_per_connection,
                'circuit_breakers': circuit_breakers,
                'ssl_context': ssl_context,
                'features': features,
                'http2_settings': http2_settings,
                'cleanup_interval_ms': cleanup_interval_ms,
                'dns_refresh_rate_ms': dns_refresh_rate_ms,
                'dns_lookup_family': dns_lookup_family,
                'dns_resolvers': dns_resolvers,
                'outlier_detection': outlier_detection
            }
        else:
            cluster['name'] = name
            cluster['sd_type'] = sd_type
            cluster['connect_timeout_ms'] = connect_timeout_ms
            cluster['per_connection_buffer_limit_bytes'] = per_connection_buffer_limit_bytes
            cluster['lb_type'] = lb_type
            cluster['ring_hash_lb_config'] = ring_hash_lb_config
            cluster['hosts'] = hosts
            cluster['service_name'] = service_name
            cluster['health_check'] = health_check
            cluster['max_requests_per_connection'] = max_requests_per_connection
            cluster['circuit_breakers'] = circuit_breakers
            cluster['ssl_context'] = ssl_context
            cluster['features'] = features
            cluster['http2_settings'] = http2_settings
            cluster['cleanup_interval_ms'] = cleanup_interval_ms
            cluster['dns_refresh_rate_ms'] = dns_refresh_rate_ms
            cluster['dns_lookup_family'] = dns_lookup_family
            cluster['dns_resolvers'] = dns_resolvers
            cluster['outlier_detection'] = outlier_detection
        return self.query_backend.put_cluster(cluster)
