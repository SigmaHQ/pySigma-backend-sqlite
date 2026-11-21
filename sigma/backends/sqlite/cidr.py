"""Exact CIDR matching for SQLite connections that opt into the function."""

from functools import lru_cache
from ipaddress import ip_address, ip_network

CIDR_FUNCTION = "sigma_cidr_contains"
# Typical IPv6 network literals fit in 50 characters. Scope identifiers and
# malformed log values may be arbitrarily long; parse those without caching.
_MAX_CACHE_KEY_LENGTH = 128


def required_sql_functions(states):
    """Read the function dependencies recorded while compiling these conditions."""
    if any(getattr(state, "sqlite_uses_cidr", False) for state in states):
        return [CIDR_FUNCTION]
    return []


def register_cidr(connection):
    """Register sigma_cidr_contains(address, network) with connection-local caches."""

    def parse_network(value):
        try:
            return ip_network(value)
        except ValueError:
            return None

    def parse_address(value):
        try:
            return ip_address(value)
        except ValueError:
            return None

    cached_network = lru_cache(maxsize=256)(parse_network)
    cached_address = lru_cache(maxsize=4096)(parse_address)

    def contains(address, network):
        if not isinstance(address, str) or not isinstance(network, str):
            return 0
        net = (
            cached_network(network)
            if len(network) <= _MAX_CACHE_KEY_LENGTH
            else parse_network(network)
        )
        addr = (
            cached_address(address)
            if len(address) <= _MAX_CACHE_KEY_LENGTH
            else parse_address(address)
        )
        return int(net is not None and addr is not None and addr in net)

    connection.create_function(CIDR_FUNCTION, 2, contains, deterministic=True)
