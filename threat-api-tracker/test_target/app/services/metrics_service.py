from prometheus_client import Counter

REQUEST_COUNT = Counter(
    'app_request_count', 'Total number of HTTP requests received'
)
