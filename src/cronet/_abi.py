"""The C ABI of libcronet.so, as ctypes declarations.

Generated from native/cronet.h by scripts/generate_binding.py.
Do not edit: change the header and regenerate, or the two descriptions
of one ABI drift apart and every read lands at the wrong offset.
"""

import ctypes

ABI_VERSION = 3
NO_TIME = -1
ERROR_ABORTED = -3
ERROR_TIMED_OUT = -7
ERROR_TOO_MANY_REDIRECTS = -31
EOF = -1

CACHE_DISABLED = 0
CACHE_IN_MEMORY = 1
CACHE_ON_DISK = 2
PRIORITY_THROTTLED = 0
PRIORITY_IDLE = 1
PRIORITY_LOWEST = 2
PRIORITY_LOW = 3
PRIORITY_MEDIUM = 4
PRIORITY_HIGHEST = 5
CALL_STARTED = 0
CALL_HEADERS = 1
CALL_DONE = 2


class CronetHeader(ctypes.Structure):
    """Mirrors `cronet_header`."""

    _fields_ = [
        ("name", ctypes.c_char_p),
        ("value", ctypes.c_char_p),
    ]


class CronetQuicHint(ctypes.Structure):
    """Mirrors `cronet_quic_hint`."""

    _fields_ = [
        ("host", ctypes.c_char_p),
        ("port", ctypes.c_int32),
        ("alternate_port", ctypes.c_int32),
    ]


class CronetEngineConfig(ctypes.Structure):
    """Mirrors `cronet_engine_config`."""

    _fields_ = [
        ("user_agent", ctypes.c_char_p),
        ("accept_language", ctypes.c_char_p),
        ("experimental_options", ctypes.c_char_p),
        ("storage_path", ctypes.c_char_p),
        ("proxy_rules", ctypes.c_char_p),
        ("proxy_bypass_rules", ctypes.c_char_p),
        ("proxy_username", ctypes.c_char_p),
        ("proxy_password", ctypes.c_char_p),
        ("quic_hints", ctypes.POINTER(CronetQuicHint)),
        ("quic_hint_count", ctypes.c_size_t),
        ("enable_quic", ctypes.c_int32),
        ("enable_http2", ctypes.c_int32),
        ("enable_brotli", ctypes.c_int32),
        ("cache_mode", ctypes.c_int32),
        ("cache_max_bytes", ctypes.c_int64),
    ]


class CronetRequest(ctypes.Structure):
    """Mirrors `cronet_request`."""

    _fields_ = [
        ("method", ctypes.c_char_p),
        ("url", ctypes.c_char_p),
        ("headers", ctypes.POINTER(CronetHeader)),
        ("header_count", ctypes.c_size_t),
        ("body", ctypes.POINTER(ctypes.c_ubyte)),
        ("body_size", ctypes.c_size_t),
        ("priority", ctypes.c_int32),
        ("max_redirects", ctypes.c_int32),
        ("disable_cache", ctypes.c_int32),
    ]


class CronetMetrics(ctypes.Structure):
    """Mirrors `cronet_metrics`."""

    _fields_ = [
        ("request_start_us", ctypes.c_int64),
        ("dns_start_us", ctypes.c_int64),
        ("dns_end_us", ctypes.c_int64),
        ("connect_start_us", ctypes.c_int64),
        ("connect_end_us", ctypes.c_int64),
        ("ssl_start_us", ctypes.c_int64),
        ("ssl_end_us", ctypes.c_int64),
        ("send_start_us", ctypes.c_int64),
        ("send_end_us", ctypes.c_int64),
        ("response_start_us", ctypes.c_int64),
        ("request_end_us", ctypes.c_int64),
        ("sent_bytes", ctypes.c_int64),
        ("received_bytes", ctypes.c_int64),
        ("socket_reused", ctypes.c_int32),
    ]


class CronetResponse(ctypes.Structure):
    """Mirrors `cronet_response`."""

    _fields_ = [
        ("status_code", ctypes.c_int32),
        ("status_text", ctypes.c_char_p),
        ("headers", ctypes.POINTER(CronetHeader)),
        ("header_count", ctypes.c_size_t),
        ("negotiated_protocol", ctypes.c_char_p),
        ("proxy_server", ctypes.c_char_p),
        ("final_url", ctypes.c_char_p),
        ("redirect_count", ctypes.c_int32),
        ("was_cached", ctypes.c_int32),
        ("error_code", ctypes.c_int32),
        ("error_message", ctypes.c_char_p),
        ("metrics", CronetMetrics),
    ]


def bind(library: ctypes.CDLL) -> None:
    """Apply every signature in this ABI to `library`.

    ctypes defaults to guessing an int return and unchecked arguments,
    which on a 64-bit pointer truncates silently. Declaring all 17
    is what makes a wrong call fail loudly at the boundary.
    """
    library.cronet_abi_version.restype = ctypes.c_int32
    library.cronet_abi_version.argtypes = []
    library.cronet_version.restype = ctypes.c_char_p
    library.cronet_version.argtypes = []
    library.cronet_engine_config_init.restype = None
    library.cronet_engine_config_init.argtypes = [ctypes.POINTER(CronetEngineConfig)]
    library.cronet_engine_create.restype = ctypes.c_void_p
    library.cronet_engine_create.argtypes = [ctypes.POINTER(CronetEngineConfig)]
    library.cronet_last_error.restype = ctypes.c_char_p
    library.cronet_last_error.argtypes = []
    library.cronet_engine_destroy.restype = None
    library.cronet_engine_destroy.argtypes = [ctypes.c_void_p]
    library.cronet_engine_start_net_log.restype = ctypes.c_int32
    library.cronet_engine_start_net_log.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_int32,
    ]
    library.cronet_engine_stop_net_log.restype = None
    library.cronet_engine_stop_net_log.argtypes = [ctypes.c_void_p]
    library.cronet_request_init.restype = None
    library.cronet_request_init.argtypes = [ctypes.POINTER(CronetRequest)]
    library.cronet_call_start.restype = ctypes.c_void_p
    library.cronet_call_start.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(CronetRequest),
    ]
    library.cronet_call_state_of.restype = ctypes.c_int32
    library.cronet_call_state_of.argtypes = [ctypes.c_void_p]
    library.cronet_call_fd.restype = ctypes.c_int
    library.cronet_call_fd.argtypes = [ctypes.c_void_p]
    library.cronet_call_wait.restype = ctypes.c_int32
    library.cronet_call_wait.argtypes = [ctypes.c_void_p, ctypes.c_int32]
    library.cronet_call_response.restype = ctypes.POINTER(CronetResponse)
    library.cronet_call_response.argtypes = [ctypes.c_void_p]
    library.cronet_call_read.restype = ctypes.c_int64
    library.cronet_call_read.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
    ]
    library.cronet_call_cancel.restype = None
    library.cronet_call_cancel.argtypes = [ctypes.c_void_p]
    library.cronet_call_free.restype = None
    library.cronet_call_free.argtypes = [ctypes.c_void_p]


#: Every function this ABI declares, for checking the library has them.
FUNCTIONS = (
    "cronet_abi_version",
    "cronet_version",
    "cronet_engine_config_init",
    "cronet_engine_create",
    "cronet_last_error",
    "cronet_engine_destroy",
    "cronet_engine_start_net_log",
    "cronet_engine_stop_net_log",
    "cronet_request_init",
    "cronet_call_start",
    "cronet_call_state_of",
    "cronet_call_fd",
    "cronet_call_wait",
    "cronet_call_response",
    "cronet_call_read",
    "cronet_call_cancel",
    "cronet_call_free",
)
