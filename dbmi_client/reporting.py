import sentry_sdk
from furl import furl


def sentry(sentry_dsn: str, release: str = None, environment: str = None, sentry_trace_rate: float = 0.0, sentry_profile_rate: float = 0.0):
    """
    Initializes the Sentry client for the current application.

    :param sentry_dsn: The DSN for the Sentry project
    :type sentry_dsn: str
    :param release: The current release of the application, defaults to None
    :type release: str, optional
    :param environment: The environment to which this applications is being deployed, defaults to None
    :type environment: str, optional
    :param sentry_trace_rate: The rate at which traces are sent, defaults to 0.0
    :type sentry_trace_rate: float, optional
    :param sentry_profile_rate: The rate at which requests are profiled, defaults to 0.0
    :type sentry_profile_rate: float, optional
    """    

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
        # Set the environment if passed
        environment=environment,
        # Set release, if passed
        release=release,
    )
