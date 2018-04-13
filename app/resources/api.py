import json
import logging
from datetime import datetime
import sys
import os
import importlib

from flask import request
from flask.ext.restful import Resource

from ..stats import get_stats
from .. import settings
from ..services import host
from ..services import query
from ..services import listener
from ..services import cluster

logger = logging.getLogger('resources.api')
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)s: %(levelname)s %(message)s')


class BackendSelector(object):

    def __init__(self):
        self.storage = self.get_storage()
        
    def get_storage(self):
        return settings.value.BACKEND_STORAGE

    def plugins_exist(self):
        return 'plugins' in os.listdir(os.getcwd())

    def assemble_plugin_backend_location(self):
        return 'plugins.{}.app.services.query'.format(self.storage) 

    def assemble_plugin_backend_class_name(self):
        return '{}QueryBackend'.format(self.storage)

    def get_query_plugin_from_location_and_name(self, backend_location, backend_name):
        try:
            query_module = importlib.import_module(backend_location)
        except ImportError:
            raise ImportError("Verify {} is a valid path".format(backend_location))

        try:
            query_backend = getattr(query_module, backend_name)()
        except AttributeError:
            raise AttributeError("Verify {} has classname {}".format(query_module, backend_name))

        return query_backend

    def select(self):
        """
        Select backend storage based on the global settings.
        """

        if self.storage == 'DynamoDB':
            return query.DynamoQueryBackend()
        elif self.storage == 'InMemory':
            return query.MemoryQueryBackend()
        elif self.storage == 'InFile':
            return query.LocalFileQueryBackend()
        elif self.plugins_exist():
            # import the query backend starting from the plugins folder
            query_location_from_plugins = self.assemble_plugin_backend_location()
            backend_name = self.assemble_plugin_backend_class_name()
            query_backend = self.get_query_plugin_from_location_and_name(
                    query_location_from_plugins, backend_name)

            return query_backend

        else:
            raise ValueError('Unknown backend storage type specified: {}'.format(self.storage))

# Run this to make sure that BACKEND_STORAGE is of known type.
BACKEND_STORAGE = BackendSelector().select()


class HostSerializer(object):

    @staticmethod
    def serialize(hosts):
        """Makes host dictionary serializable

        :param hosts: list of hosts, each host is defined by dict host info
        :type hosts: dict

        :returns: list of host info dictionaries
        :rtype: list of dict
        """

        for _host in hosts:
            _host['last_check_in'] = str(_host['last_check_in'])

        return hosts

class Registration(Resource):

    def get(self, service):
        """Return all the hosts registered for this service"""

        host_service = host.HostService(BACKEND_STORAGE)
        hosts = host_service.list(service)
        response = {
            'service': service,
            'env': settings.value.APPLICATION_ENV,
            'hosts': HostSerializer.serialize(hosts)
        }
        return response, 200

    def post(self, service):
        """Update or add a service registration given the host information in this request"""

        ip_address = self._get_param('ip', None)
        if not ip_address and self._get_param('auto_ip', None):
            # Discovery ELB is the single proxy, take last ip in route
            forwarded_for = request.remote_addr
            parts = forwarded_for.split('.')
            # 192.168.0.0/16
            valid = (len(parts) == 4 and
                     int(parts[0]) == 192 and
                     int(parts[1]) == 168 and
                     0 <= int(parts[2]) <= 255 and
                     0 <= int(parts[3]) <= 255)
            if valid:
                ip_address = forwarded_for
                logger.info('msg="auto_ip success" service={}, auto_ip={}'
                            .format(service, ip_address))
            else:
                logger.warn('msg="auto_ip invalid" service={} auto_ip={}'
                            .format(service, ip_address))
        service_repo_name = self._get_param('service_repo_name', '')
        port = int(self._get_param('port', -1))
        revision = self._get_param('revision', None)
        last_check_in = datetime.utcnow()
        tags = self._get_param('tags', '{}')

        try:
            tags = json.loads(tags)
        except ValueError as ex:
            logger.exception("Failed to parse tags json: {}. Exception: {}".format(tags, ex))
            return {"error": "Invalid json supplied in tags"}, 400

        host_service = host.HostService(BACKEND_STORAGE)
        success = host_service.update(service, ip_address, service_repo_name,
                                      port, revision, last_check_in, tags)

        statsd = get_stats("registration")
        if success:
            response_code = 200
            statsd.incr("%s.success" % service)
        else:
            response_code = 400
            statsd.incr("%s.failure" % service)
        return {}, response_code

    def delete(self, service, ip_address):
        """Delete a host from dynamo"""

        host_service = host.HostService(BACKEND_STORAGE)
        success = host_service.delete(service, ip_address)
        response_code = 200 if success else 400
        return {}, response_code

    def _get_param(self, param, default=None):
        """Return the request parameter.  Returns default if the param was not found"""

        return request.form[param] if param in request.form else default


class RepoRegistration(Resource):

    def get(self, service_repo_name):
        """Return all the hosts that belong to the service_repo_name"""

        host_service = host.HostService(BACKEND_STORAGE)
        hosts = host_service.list_by_service_repo_name(service_repo_name)
        response = {
            'service_repo_name': service_repo_name,
            'env': settings.value.APPLICATION_ENV,
            'hosts': HostSerializer.serialize(hosts)
        }
        return response, 200


class LoadBalancing(Resource):

    def post(self, service, ip_address=None):
        weight = request.form.get('load_balancing_weight')
        if not weight:
            return {"error": "Required parameter 'weight' is missing."}, 400

        try:
            weight = int(weight)
        except ValueError:
            weight = None

        if not weight or not 1 <= weight <= 100:
            return {"error": ("Invalid load_balancing_weight. Supply an "
                              "integer between 1 and 100.")}, 400

        host_service = host.HostService(BACKEND_STORAGE)

        if ip_address:
            if not host_service.set_tag(service, ip_address, 'load_balancing_weight', weight):
                return {"error": "Host not found"}, 404
        else:
            host_service.set_tag_all(service, 'load_balancing_weight', weight)

        return "", 204


class Listener(Resource):
    def get(self, service_cluster=None, service_node=None):
        """Return all the listeners registered for this service"""

        listener_service = listener.ListenerService(BACKEND_STORAGE)
        listeners = listener_service.list()
        cleaned_listeners = []
        for l in listeners:
            cleaned_listeners.append({k: v for k,v in l.iteritems() if v is not None})
        response = {
            'listeners': cleaned_listeners
        }
        return response, 200

    def post(self, service_cluster=None, service_node=None):
        """Update or add a listener given the host information in this request"""
        name = self._get_param('name', None)
        address = self._get_param('address', None)
        if address is None:
            logger.exception("Address parameter is required")
            return {"error": "Address parameter is required"}, 400

        filters = self._get_param('filters', '[]')
        try:
            filters = json.loads(filters)
        except ValueError as ex:
            logger.exception("Failed to parse filters json: {}. Exception: {}".format(filters, ex))
            return {"error": "Invalid json supplied in filters"}, 400

        ssl_context = self._get_param('ssl_context', None)
        if ssl_context is not None:
            try:
                ssl_context = json.loads(ssl_context)
            except ValueError as ex:
                logger.exception("Failed to parse ssl_context json: {}. Exception: {}".format(ssl_context, ex))
                return {"error": "Invalid json supplied in ssl_context"}, 400

        bind_to_port = bool(self._get_param('bind_to_port', True))
        use_proxy_proto = bool(self._get_param('use_proxy_proto', False))
        use_original_dst = bool(self._get_param('use_original_dst', False))
        per_connection_buffer_limit_bytes = self._get_param('per_connection_buffer_limit_bytes', None)
        drain_type = str(self._get_param('drain_type', 'default'))

        listener_service = listener.ListenerService(BACKEND_STORAGE)
        success = listener_service.update(
            name,
            address,
            filters,
            ssl_context,
            bind_to_port,
            use_proxy_proto,
            use_original_dst,
            per_connection_buffer_limit_bytes,
            drain_type
        )

        statsd = get_stats("listener")
        if success:
            response_code = 200
            statsd.incr("listener.success")
        else:
            response_code = 400
            statsd.incr("listener.failure")
        return {}, response_code

    def _get_param(self, param, default=None):
        """Return the request parameter.  Returns default if the param was not found"""

        return request.form[param] if param in request.form else default


class Cluster(Resource):
    def get(self, service_cluster=None, service_node=None):
        """Return all the clusters registered for this service"""

        cluster_service = cluster.ClusterService(BACKEND_STORAGE)
        clusters = cluster_service.list()
        cleaned_clusters = []
        for cl in clusters:
            cleaned_cluster = {}
            for k,v in cl.iteritems():
                if v is None:
                    continue
                if k == 'sd_type':
                    k = 'type'
                cleaned_cluster[k] = v
            cleaned_clusters.append(cleaned_cluster)
        response = {
            'clusters': cleaned_clusters
        }
        return response, 200

    def post(self, service_cluster=None, service_node=None):
        """Update or add a cluster given the host information in this request"""
        name = self._get_param('name', None)
        sd_type = self._get_param('type', None)
        connect_timeout_ms = self._get_param('connect_timeout_ms', None)
        per_connection_buffer_limit_bytes = self._get_param('per_connection_buffer_limit_bytes', 1048576)
        lb_type = self._get_param('lb_type', None)

        if name is None:
            logger.exception("name parameter is required")
            return {"error": "name parameter is required"}, 400

        if sd_type is None:
            logger.exception("type parameter is required")
            return {"error": "type parameter is required"}, 400

        if connect_timeout_ms is None:
            logger.exception("connect_timeout_ms parameter is required")
            return {"error": "connect_timeout_ms parameter is required"}, 400

        if lb_type is None:
            logger.exception("lb_type parameter is required")
            return {"error": "lb_type parameter is required"}, 400

        ring_hash_lb_config = self._get_param('ring_hash_lb_config', None)
        hosts = self._get_param('hosts', None)
        service_name = self._get_param('service_name', None)
        health_check = self._get_param('health_check', None)
        max_requests_per_connection = self._get_param('max_requests_per_connection', None)
        circuit_breakers = self._get_param('circuit_breakers', None)
        ssl_context = self._get_param('ssl_context', None)
        features = self._get_param('features', None)
        http2_settings = self._get_param('http2_settings', None)
        cleanup_interval_ms = self._get_param('cleanup_interval_ms', None)
        dns_refresh_rate_ms = self._get_param('dns_refresh_rate_ms', None)
        dns_lookup_family = self._get_param('dns_lookup_family', None)
        dns_resolvers = self._get_param('dns_resolvers', None)
        outlier_detection = self._get_param('outlier_detection', None)


        if ring_hash_lb_config is not None:
            try:
                ring_hash_lb_config = json.loads(ring_hash_lb_config)
            except ValueError as ex:
                logger.exception("Failed to parse ring_hash_lb_config json: {}. Exception: {}".format(ring_hash_lb_config, ex))
                return {"error": "Invalid json supplied in ring_hash_lb_config"}, 400

        if hosts is not None:
            try:
                hosts = json.loads(hosts)
            except ValueError as ex:
                logger.exception("Failed to parse hosts json: {}. Exception: {}".format(hosts, ex))
                return {"error": "Invalid json supplied in hosts"}, 400

        if health_check is not None:
            try:
                health_check = json.loads(health_check)
            except ValueError as ex:
                logger.exception("Failed to parse health_check json: {}. Exception: {}".format(health_check, ex))
                return {"error": "Invalid json supplied in health_check"}, 400

        if circuit_breakers is not None:
            try:
                circuit_breakers = json.loads(circuit_breakers)
            except ValueError as ex:
                logger.exception("Failed to parse circuit_breakers json: {}. Exception: {}".format(circuit_breakers, ex))
                return {"error": "Invalid json supplied in circuit_breakers"}, 400

        if ssl_context is not None:
            try:
                ssl_context = json.loads(ssl_context)
            except ValueError as ex:
                logger.exception("Failed to parse ssl_context json: {}. Exception: {}".format(ssl_context, ex))
                return {"error": "Invalid json supplied in ssl_context"}, 400

        if http2_settings is not None:
            try:
                http2_settings = json.loads(http2_settings)
            except ValueError as ex:
                logger.exception("Failed to parse http2_settings json: {}. Exception: {}".format(http2_settings, ex))
                return {"error": "Invalid json supplied in http2_settings"}, 400

        if dns_resolvers is not None:
            try:
                dns_resolvers = json.loads(dns_resolvers)
            except ValueError as ex:
                logger.exception("Failed to parse dns_resolvers json: {}. Exception: {}".format(dns_resolvers, ex))
                return {"error": "Invalid json supplied in dns_resolvers"}, 400

        if outlier_detection is not None:
            try:
                outlier_detection = json.loads(outlier_detection)
            except ValueError as ex:
                logger.exception("Failed to parse outlier_detection json: {}. Exception: {}".format(outlier_detection, ex))
                return {"error": "Invalid json supplied in outlier_detection"}, 400

        cluster_service = cluster.ClusterService(BACKEND_STORAGE)
        success = cluster_service.update(
            name,
            sd_type,
            connect_timeout_ms,
            per_connection_buffer_limit_bytes,
            lb_type,
            ring_hash_lb_config,
            hosts,
            service_name,
            health_check,
            max_requests_per_connection,
            circuit_breakers,
            ssl_context,
            features,
            http2_settings,
            cleanup_interval_ms,
            dns_refresh_rate_ms,
            dns_lookup_family,
            dns_resolvers,
            outlier_detection
        )

        statsd = get_stats("cluster")
        if success:
            response_code = 200
            statsd.incr("cluster.success")
        else:
            response_code = 400
            statsd.incr("cluster.failure")
        return {}, response_code

    def _get_param(self, param, default=None):
        """Return the request parameter.  Returns default if the param was not found"""

        return request.form[param] if param in request.form else default
