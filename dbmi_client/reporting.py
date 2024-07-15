import sentry_sdk
from furl import furl

def config(service, sentry_dsn=None, sentry_trace_rate=0.0, sentry_profile_rate=0.0):

    def filter_transactions(event, hint):
        parsed_url = furl(event["request"]["url"])

        # Do not sample healthcheck requests
        if parsed_url.path == "/healthcheck":
            return None

        return event

    # Setup sentry
    sentry_sdk.init(
        dsn=sentry_dsn,
        # Filter transactions
        before_send_transaction=filter_transactions,
        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for tracing.
        traces_sample_rate=sentry_trace_rate,
        # Set profiles_sample_rate to 1.0 to profile 100%
        # of sampled transactions.
        # We recommend adjusting this value in production.
        profiles_sample_rate=sentry_profile_rate,
    )
