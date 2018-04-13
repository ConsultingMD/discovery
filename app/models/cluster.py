from .. import settings
from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, NumberAttribute, UTCDateTimeAttribute, JSONAttribute, BooleanAttribute
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection


class Cluster(Model):
    """
    A DynamoDB Server Cluster.
    """

    class Meta:
        table_name = settings.value.DYNAMODB_TABLE_HOSTS
        if settings.value.APPLICATION_ENV == 'development':
            host = settings.value.DYNAMODB_URL


    name = UnicodeAttribute(hash_key=True)
    sd_type = UnicodeAttribute()
    connect_timeout_ms = NumberAttribute()
    per_connection_buffer_limit_bytes = NumberAttribute()
    lb_type = UnicodeAttribute()
    ring_hash_lb_config = JSONAttribute(null=True)
    hosts = JSONAttribute(null=True)
    service_name = UnicodeAttribute(null=True)
    health_check = JSONAttribute(null=True)
    max_requests_per_connection = NumberAttribute(null=True)
    circuit_breakers = JSONAttribute(null=True)
    ssl_context = JSONAttribute(null=True)
    features = UnicodeAttribute(null=True)
    http2_settings = JSONAttribute(null=True)
    cleanup_interval_ms = NumberAttribute(null=True)
    dns_refresh_rate_ms = NumberAttribute(null=True)
    dns_lookup_family = UnicodeAttribute(null=True)
    dns_resolvers = JSONAttribute(null=True)
    outlier_detection = JSONAttribute(null=True)
