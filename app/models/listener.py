from .. import settings
from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, NumberAttribute, UTCDateTimeAttribute, JSONAttribute, BooleanAttribute
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection


class Listener(Model):
    """
    A DynamoDB Server Listener.
    """

    class Meta:
        table_name = settings.value.DYNAMODB_TABLE_HOSTS
        if settings.value.APPLICATION_ENV == 'development':
            host = settings.value.DYNAMODB_URL

    address = UnicodeAttribute(hash_key=True)
    name = UnicodeAttribute(null=True)
    filters = JSONAttribute()
    ssl_context= JSONAttribute()
    bind_to_port = BooleanAttribute()
    use_proxy_proto = BooleanAttribute()
    use_original_dst = BooleanAttribute()
    per_connection_buffer_limit_bytes = NumberAttribute()
    drain_type = UnicodeAttribute()
