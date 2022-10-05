import inspect
import pkgutil
from pathlib import Path
from importlib import import_module

from django.conf import settings
from dbmi_client.settings import dbmi_settings

import logging
logger = logging.getLogger(__name__)


class ProviderFactory(object):
    """
    This class manages the creation of Provider instances based on the identifier/provider
    and client ID.
    """
    @classmethod
    def provider_for_client_id(cls, client_id):
        """
        Returns the provider identifier for the given client ID.

        :param client_id: The client ID of the auth provider to check
        :type client_id: str
        :return: The identifier of the provider
        :rtype: str
        """
        try:
            # Match the client ID to an authentication provider
            return dbmi_settings.AUTH_CLIENTS[client_id]["PROVIDER"]

        except Exception:
            raise Exception(f"No matching authentication provider for client id: '{client_id}'")

    @classmethod
    def create(cls, client_id, callback_url, **kwargs):

        identifier = None
        try:
            # Match the client ID to an authentication provider
            configuration = dbmi_settings.AUTH_CLIENTS[client_id]
            identifier = configuration["PROVIDER"]

            # Get the class for the provider
            provider_class = next(
                provider for provider in ProviderFactory.providers()
                if getattr(provider, 'identifier') == identifier
            )

            # Instantiate it
            provider = provider_class(**{
                'domain': configuration["DOMAIN"],
                'client_id': client_id,
                'client_secret': configuration["CLIENT_SECRET"],
                'scope': configuration["SCOPE"],
                'callback_url': callback_url,
                **kwargs
            })

            return provider

        except StopIteration:
            raise Exception(f"No implemented authentication provider for: '{identifier}' / '{client_id}'")

        except Exception:
            raise Exception(f"No matching authentication provider for client id: '{client_id}'")

    #
    # META
    #

    @classmethod
    def providers(cls, filter=None):
        """
        This method returns a complete list of all subclasses inherited from Provider. The list contains an
        instance of each class. If specified, the filter will limit the set of subclasses returned based
        on a key-value check on the class properties.
        :param filter: A dictionary defining a filter to apply to the returned list of subclasses.
        :return: list
        """
        provider_class = getattr(import_module('dbmi_client.provider.provider'), "Provider")
        subclasses = []
        for (_, name, _) in pkgutil.iter_modules([str(Path(__file__).parent)]):
            imported_module = import_module('.' + name, package='dbmi_client.provider')
            for i in dir(imported_module):
                attribute = getattr(imported_module, i)

                # Ensure this is a valid subclass of provider
                if inspect.isclass(attribute) and issubclass(attribute, provider_class) and attribute not in subclasses:

                    # Check for child providers
                    if hasattr(attribute, 'providers'):
                        for provider_subclass in getattr(attribute, 'providers')(filter=filter):
                            if inspect.isclass(provider_subclass) and issubclass(provider_subclass, provider_class) \
                                    and provider_subclass not in subclasses:
                                subclasses.append(provider_subclass)
                            else:
                                logger.warning('Provider "{}" returned a child provider "{}" that did not qualify '
                                               'as provider'.format(attribute, provider_subclass))

                    # Ensure a base set of required properties exist
                    if not getattr(attribute, 'identifier', False):
                        continue

                    # Check filter
                    if filter:
                        matched = False
                        for key, value in filter.items():
                            if getattr(attribute, key, None) != value:
                                break
                        else:
                            matched = True

                        # Check result
                        if not matched:
                            continue

                    # Passed all tests, this subclass is a valid Provider
                    subclasses.append(attribute)

        return subclasses
