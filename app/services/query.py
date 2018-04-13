import abc
import logging
import os
import pickle
import tempfile

from ..stats import get_stats
from ..models.host import Host
from ..models.listener import Listener
from ..models.cluster import Cluster


class QueryBackend(object):
    __metaclass__ = abc.ABCMeta
    """A storage backend that can store and retrieve host data.

    This is modeled off of the dynamodb python API, but made more
    general so users not on Amazon can use discovery.
    """

    @abc.abstractmethod
    def query(self, service):
        """Returns a generator of host dicts for the given service.

        Note that this will NOT deal with how timing out entries -- that is
        a concern of the caller.

        :param service: service of the hosts to retrieve

        :type service: str

        :returns: hosts associated with this service
        :rtype: list(dict)
        """

        pass

    @abc.abstractmethod
    def query_secondary_index(self, service_repo_name):
        """For backends that support secondary indices, allows more efficient querying.

        :param service_repo_name: service_repo_name to retrieve associated hosts for

        :type service_repo_name: str

        :returns: hosts associated with this service_repo_name
        :rtype: list(dict)
        """

        pass

    @abc.abstractmethod
    def get(self, service, ip_address):
        """Fetches the single host associated with the given service and ip_address

        :param service: the service of the host to get
        :param ip_address: the ip_address of the host to get

        :type service: str
        :type ip_address: str

        :returns: a single host if one exists, None otherwise
        :rtype: dict
        """

        pass

    @abc.abstractmethod
    def get_listener(self, address):
        """Fetches a listener by address.

        :param address: the address of the listener, e.g. "tcp://127.0.0.1:80"

        :type address: str

        :returns: a single listener if one exists, None otherwise
        :rtype: dict
        """

        pass

    @abc.abstractmethod
    def get_listeners(self):
        """Fetches all listeners.

        :returns: a list of listeners
        :rtype: list
        """

        pass

    @abc.abstractmethod
    def get_cluster(self, name):
        """Fetches a cluster by name.

        :param name: the name of the cluster, e.g. "jarvis"

        :type name: str

        :returns: a single cluster if one exists, None otherwise
        :rtype: dict
        """

        pass

    @abc.abstractmethod
    def get_clusters(self):
        """Fetches all clusters.

        :returns: a list of clusters
        :rtype: list
        """

        pass

    @abc.abstractmethod
    def put(self, host):
        """Attempts to store the given host

        :param host: host entry to store

        :type host: dict

        :returns: True if put successful, False otherwise
        :rtype: bool
        """

        pass

    @abc.abstractmethod
    def put_listener(self, listener):
        """Attempts to store the given listener

        :param listener: listener entry to store

        :type listener: dict

        :returns: True if put successful, False otherwise
        :rtype: bool
        """

        pass

    @abc.abstractmethod
    def put_cluster(self, cluster):
        """Attempts to store the given cluster

        :param cluster: cluster entry to store

        :type cluster: dict

        :returns: True if put successful, False otherwise
        :rtype: bool
        """

        pass

    @abc.abstractmethod
    def delete(self, service, ip_address):
        """Deletes the given host for the given service/ip_address

        :param service: the service of the host to delete
        :param ip_address: the ip_address of the host to delete

        :type service: str
        :type ip_address: str

        :returns: True if delete successful, False otherwise
        :rtype: bool
        """

        pass

    @abc.abstractmethod
    def delete_listener(self, address):
        """Deletes the given listener for the given address

        :param address: the address of the listener to delete

        :type address: str

        :returns: True if delete successful, False otherwise
        :rtype: bool
        """

        pass

    @abc.abstractmethod
    def delete_cluster(self, name):
        """Deletes the given cluster for the given name

        :param name: the name of the cluster to delete

        :type name: str

        :returns: True if delete successful, False otherwise
        :rtype: bool
        """

        pass

    def batch_put(self, hosts):
        '''Batch write interface for backends which support more efficient batch storing methods.

        Note: even for backends that support this, do NOT assume that it is atomic! That depends on
        the backend, but is not a semantic enforced by this API. If this fails, it is possible that
        some values have been partially written. This needs to be handled by the caller.

        :param hosts: list of host dicts to write

        :type hosts: list(dict)

        :returns: True if all writes successful, False if 1 or more fail
        :rtype: bool
        '''
        return all(map(self.store, hosts))


# TODO need to factor out the statsd dep
class MemoryQueryBackend(QueryBackend):
    def __init__(self):
        self.data = {}

    def _list_all(self):
        """A generator over every host that has been stored."""

        for service in self.data.keys():
            for r in self.query(service):
                yield r

    def query(self, service):
        ip_map = self.data.get(service)
        if ip_map is None:
            return

        for ip_address, host_dict in ip_map.items():
            _host = host_dict.copy()
            _host['service'] = service
            _host['ip_address'] = ip_address
            yield _host

    # TODO this can certainly be made faster, but I don't know if that's
    # really necessary...
    def query_secondary_index(self, service_repo_name):
        for host in self._list_all():
            if host['service_repo_name'] == service_repo_name:
                yield host

    def get(self, service, ip_address):
        ip_map = self.data.get(service)
        if ip_map is None:
            return None

        host_dict = ip_map.get(ip_address)
        if host_dict is None:
            return None

        host = host_dict.copy()
        host['service'] = service
        host['ip_address'] = ip_address
        return host

    def get_listener(self, address):
        listeners = self.data.get('_listeners')
        if listeners is None:
            return None

        listener = listeners.get(address)
        if listener is None:
            return None

        return listener

    def get_listeners(self):
        listeners = self.data.get('_listeners')
        if listeners is None:
            return None
        return listeners.values()

    def get_cluster(self, name):
        clusters = self.data.get('_clusters')
        if clusters is None:
            return None

        cluster = clusters.get(name)
        if cluster is None:
            return None

        return cluster

    def get_clusters(self):
        clusters = self.data.get('_clusters')
        if clusters is None:
            return None
        return clusters.values()

    def put(self, host):
        service = host['service']
        ip_address = host['ip_address']

        ip_map = self.data.get(service)
        if ip_map is None:
            ip_map = {}
            self.data[service] = ip_map

        host_dict = host.copy()
        del host_dict['service']
        del host_dict['ip_address']

        ip_map[ip_address] = host_dict
        return True

    def put_listener(self, listener):
        listeners = self.data.get('_listeners')
        if listeners is None:
            listeners = {}
            self.data['_listeners'] = listeners

        if not (listener['address'] in listeners):
            listeners[listener['address']] = listener

        return True

    def put_cluster(self, cluster):
        clusters = self.data.get('_clusters')
        if clusters is None:
            clusters = {}
            self.data['_clusters'] = clusters

        if not (cluster['name'] in clusters):
            clusters[cluster['name']] = cluster

        return True

    def delete(self, service, ip_address):
        ip_map = self.data.get(service)
        if ip_map is None:
            return False

        host_dict = ip_map.get(ip_address)
        if host_dict is None:
            return False

        del ip_map[ip_address]
        if len(ip_map) == 0:
            del self.data[service]
        return True

    def delete_listener(self, address):
        listeners = self.data.get('_listeners')
        if listeners is None:
            return False

        if address in listeners:
            del listeners[address]

        if len(listeners) == 0:
            del self.data['_listeners']

        return True

    def delete_cluster(self, name):
        clusters = self.data.get('_clusters')
        if clusters is None:
            return False

        if name in clusters:
            del clusters[name]

        if len(clusters) == 0:
            del self.data['_clusters']

        return True


class LocalFileQueryBackend(QueryBackend):
    def __init__(self, file=tempfile.TemporaryFile().name):
        self.backend = MemoryQueryBackend()
        self.file = file
        if os.path.isfile(self.file) and os.stat(self.file).st_size > 0:
            self.backend.data = pickle.load(open(self.file))

    def _save(self):
        """Saves the data information to local file."""

        pickle.dump(self.backend.data, open(self.file, 'w'))

    def query(self, service):
        return self.backend.query(service)

    def query_secondary_index(self, service_repo_name):
        return self.backend.query_secondary_index(service_repo_name)

    def get(self, service, ip_address):
        return self.backend.get(service, ip_address)

    def get_listener(self, address):
        return self.backend.get_listener(address)

    def get_listeners(self):
        return self.backend.get_listeners()

    def get_cluster(self, name):
        return self.backend.get_cluster(name)

    def get_clusters(self):
        return self.backend.get_clusters()

    def put(self, host):
        try:
            return self.backend.put(host)
        finally:
            self._save()

    def put_listener(self, listener):
        try:
            return self.backend.put_listener(listener)
        finally:
            self._save()

    def put_cluster(self, cluster):
        try:
            return self.backend.put_cluster(cluster)
        finally:
            self._save()

    def delete(self, service, ip_address):
        try:
            return self.backend.delete(service, ip_address)
        finally:
            self._save()

    def delete_listener(address):
        try:
            return self.backend.delete_listener(address)
        finally:
            self._save()

    def delete_cluster(name):
        try:
            return self.backend.delete_cluster(name)
        finally:
            self._save()

class DynamoQueryBackend(QueryBackend):
    def query(self, service):
        return self._read_cursor(Host.query(service))

    def query_secondary_index(self, service_repo_name):
        return self._read_cursor(Host.service_repo_name_index.query(service_repo_name))

    def get(self, service, ip_address):
        try:
            host = Host.get(service, ip_address)
            if host is None:
                return None
            return self._pynamo_host_to_dict(host)
        except Host.DoesNotExist:
            return None

    def get_listener(self, address):
        try:
            listener = Listener.get(address)
            if listener is None:
                return None
            return self._pynamo_listener_to_dict(listener)
        except Listener.DoesNotExist:
            return None

    def get_listeners(self):
        try:
            listeners = Listener.scan()
            if listeners is None:
                return None
            return [self._pynamo_listener_to_dict(listener) for listener in listeners]
        except Listener.DoesNotExist:
            return None

    def get_cluster(self, name):
        try:
            cluster = Cluster.get(name)
            if cluster is None:
                return None
            return self._pynamo_cluster_to_dict(cluster)
        except Cluster.DoesNotExist:
            return None

    def get_clusters(self):
        try:
            clusters = Cluster.scan()
            if clusters is None:
                return None
            return [self._pynamo_cluster_to_dict(cluster) for cluster in clusters]
        except Cluster.DoesNotExist:
            return None

    def put(self, host):
        self._dict_to_pynamo_host(host).save()

    def put_listener(self, listener):
        self._dict_to_pynamo_listener(listener).save()

    def put_cluster(self, cluster):
        self._dict_to_pynamo_cluster(cluster).save()

    def batch_put(self, hosts):
        """
        Note! Batched writes in pynamo are NOT ATOMIC. Batch writes are
        done in groups of 25 with pynamo handling retries for partial failures
        in a batch. It's possible that retries can be exhausted and we could
        end up in a state where some weights were written and others weren't,
        so external users should always ensure that weights were all
        propagated and explicitly retry if not.

        It's also possible that we're overriding newer data from hosts since
        we're putting the whole host object rather than just updating an
        individual field. This should be OK in practice as the time frame is
        short and the next host update will return things to normal.
        """

        # TODO need to look at the exceptions dynamo can throw here, catch, return False
        with Host.batch_write() as batch:
            for host in hosts:
                batch.save(self._dict_to_pynamo_host(host))
        return True

    def delete(self, service, ip_address):
        """
        Technically we should not have several entries for the given service and ip address.
        But there is no guarantee that it must be the case. Here we verify that it's strictly
        one registered service/ip.
        """

        statsd = get_stats('service.host')
        hosts = list(self._read_cursor(Host.query(service, ip_address__eq=ip_address)))
        if len(hosts) == 0:
            logging.error(
                "Delete called for nonexistent host: service=%s ip=%s" % (service, ip_address)
            )
            return False
        elif len(hosts) > 1:
            logging.error(
                "Returned more than 1 result for query %s %s.  Aborting the delete"
                % (service, ip_address)
            )
            return False
        else:
            self._dict_to_pynamo_host(hosts[0]).delete()
            statsd.incr("delete.%s" % service)
            return True

    def delete_listener(self, addr):
        """
        Technically we should not have several entries for the given service and ip address.
        But there is no guarantee that it must be the case. Here we verify that it's strictly
        one registered service/ip.
        """

        statsd = get_stats('service.listener')
        listeners = list(self._read_cursor(Listener.query(addr)))
        if len(listeners) == 0:
            logging.error(
                "Delete called for nonexistent listener: addr=%s" % (addr,)
            )
            return False
        elif len(listeners) > 1:
            logging.error(
                "Returned more than 1 result for query %s.  Aborting the delete"
                % (addr,)
            )
            return False
        else:
            self._dict_to_pynamo_listener(listeners[0]).delete()
            statsd.incr("delete.%s" % addr)
            return True

    def delete_cluster(self, name):
        """
        Technically we should not have several entries for the given service and ip address.
        But there is no guarantee that it must be the case. Here we verify that it's strictly
        one registered service/ip.
        """

        statsd = get_stats('service.cluster')
        clusters = list(self._read_cursor(Listener.query(name)))
        if len(clusters) == 0:
            logging.error(
                "Delete called for nonexistent cluster: name=%s" % (name,)
            )
            return False
        elif len(clusters) > 1:
            logging.error(
                "Returned more than 1 result for query %s.  Aborting the delete"
                % (name,)
            )
            return False
        else:
            self._dict_to_pynamo_cluster(clusters[0]).delete()
            statsd.incr("delete.%s" % name)
            return True

    def _read_cursor(self, cursor):
        """Converts a pynamo cursor into a generator.

        :param cursor: pynamo cursor

        :type cursor: TODO dig it up, some pynamo nonsense

        :returns: generator based on the cursor
        :retype: generator(dict)
        """

        for host in cursor:
            yield self._pynamo_host_to_dict(host)

    def _pynamo_host_to_dict(self, host):
        """Converts a pynamo host into a dict.

        :param host: pynamo host

        :type host: Host

        :returns: dictionary with host info
        :rtype: dict
        """

        _host = {}
        _host['service'] = host.service
        _host['ip_address'] = host.ip_address
        _host['service_repo_name'] = host.service_repo_name
        _host['port'] = host.port
        _host['revision'] = host.revision
        _host['last_check_in'] = host.last_check_in
        _host['tags'] = host.tags
        return _host

    def _pynamo_listener_to_dict(self, listener):
        """Converts a pynamo listener into a dict.

        :param listener: pynamo listener

        :type listener: Listener

        :returns: dictionary with listener info
        :rtype: dict
        """

        _listener = {}
        _listener['name'] = listener.name
        _listener['address'] = listener.address
        _listener['filters'] = listener.filters
        _listener['ssl_context'] = listener.ssl_context
        _listener['bind_to_port'] = listener.bind_to_port
        _listener['use_proxy_proto'] = listener.use_proxy_proto
        _listener['use_original_dst'] = listener.use_original_dst
        _listener['per_connection_buffer_limit_bytes'] = listener.per_connection_buffer_limit_bytes
        _listener['drain_type'] = listener.drain_type
        return _listener

    def _pynamo_cluster_to_dict(self, cluster):
        """Converts a pynamo cluster into a dict.

        :param cluster: pynamo cluster

        :type cluster: Cluster

        :returns: dictionary with cluster info
        :rtype: dict
        """

        _cluster = {}

        _cluster['name'] = cluster.name
        _cluster['sd_type'] = cluster.sd_type
        _cluster['connect_timeout_ms'] = cluster.connect_timeout_ms
        _cluster['per_connection_buffer_limit_bytes'] = cluster.per_connection_buffer_limit_bytes
        _cluster['lb_type'] = cluster.lb_type
        _cluster['ring_hash_lb_config'] = cluster.ring_hash_lb_config
        _cluster['hosts'] = cluster.hosts
        _cluster['service_name'] = cluster.service_name
        _cluster['health_check'] = cluster.health_check
        _cluster['max_requests_per_connection'] = cluster.max_requests_per_connection
        _cluster['circuit_breakers'] = cluster.circuit_breakers
        _cluster['ssl_context'] = cluster.ssl_context
        _cluster['features'] = cluster.features
        _cluster['http2_settings'] = cluster.http2_settings
        _cluster['cleanup_interval_ms'] = cluster.cleanup_interval_ms
        _cluster['dns_refresh_rate_ms'] = cluster.dns_refresh_rate_ms
        _cluster['dns_lookup_family'] = cluster.dns_lookup_family
        _cluster['dns_resolvers'] = cluster.dns_resolvers
        _cluster['outlier_detection'] = cluster.outlier_detection

        return _cluster

    def _dict_to_pynamo_host(self, host):
        """Converts a dict to a pynamo host.

        Note that if any keys are missing, there will be an error.

        :param host: dict with host info

        :type host: dict

        :returns: pynamo Host
        :rtype: Host
        """

        return Host(service=host['service'],
                    ip_address=host['ip_address'],
                    service_repo_name=host['service_repo_name'],
                    port=host['port'],
                    revision=host['revision'],
                    last_check_in=host['last_check_in'],
                    tags=host['tags'])


    def _dict_to_pynamo_listener(self, listener):
        """Converts a dict to a pynamo listener.

        Note that if any keys are missing, there will be an error.

        :param listener: dict with listener info

        :type listener: dict

        :returns: pynamo Listener
        :rtype: Listener
        """

        listener_attrs = listener.copy()
        return Listener(**listener_attrs)

    def _dict_to_pynamo_cluster(self, cluster):
        """Converts a dict to a pynamo cluster.

        Note that if any keys are missing, there will be an error.

        :param cluster: dict with cluster info

        :type cluster: dict

        :returns: pynamo Cluster
        :rtype: Cluster
        """

        cluster_attrs = cluster.copy()
        return Cluster(**cluster_attrs)
