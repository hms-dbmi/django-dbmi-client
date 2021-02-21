import requests
import json
from furl import furl

from django.core.mail import send_mail
from dbmi_client.settings import dbmi_settings

# Get the app logger
import logging
logger = logging.getLogger(dbmi_settings.LOGGER_NAME)


class Support:
    """
    This class manages support requests with Jira Support Desk. Utility methods
    are provided designed to submit requests on behalf of users.
    """
    @classmethod
    def _headers(cls):
        """
        Returns headers used to qualify requests to Jira's API
        """
        return {
            'X-ExperimentalApi': 'true'
        }

    @classmethod
    def _auth(cls):
        """
        Returns the authentication object used to authenticate calls to Jira's
        API.
        """
        if not dbmi_settings.JIRA_USERNAME or not dbmi_settings.JIRA_TOKEN:
            raise SystemError("Cannot use Support without configured Jira credentials")

        return (dbmi_settings.JIRA_USERNAME, dbmi_settings.JIRA_TOKEN)

    @classmethod
    def _get_paged_results(cls, url, filter=None, limit=None):
        """
        Accepts a URL and returns all of the paged results, combined. Only
        simple top-level key-value matching is supported.

        :param url: The URL to fetch from
        :type url: str
        :param filter: A lambda to filter results on
        :type filter: lambda, defaults to None
        :param limit: A number to limit results too
        :type limit: int, defaults to None
        :return: A list of all objects returned
        :rtype: list
        """
        content = None
        try:
            # Collect results
            objects = []

            # Page results
            next_url = url
            while next_url is not None:

                # Pull a page
                response = requests.get(next_url, headers=cls._headers(), auth=cls._auth())
                content = response.content
                response.raise_for_status()

                # Check for filter and apply it
                if filter and filter(object):

                    # Append the matched object
                    objects.append(object)

                else:
                    # Parse response
                    objects.extend(response.json().get("values", []))

                # Check limit
                if limit and len(objects) >= limit:
                    return objects

                # Check for next URL
                next_url = response.json().get("_links", {}).get("next", None)

            return objects

        except Exception as e:
            logger.exception(
                f"Support: Error querying Jira: {e}",
                exc_info=True,
                extra={
                    "url": url,
                    "content": content,
                }
            )

    @classmethod
    def get_organization(cls, name=None):
        """
        Returns a list of current organizations for the service desk. If passed,
        filters by name.

        :param email: The email of the customer to find, defaults to None
        :type email: str, optional
        """
        # Make the request
        url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
        url.path.segments.extend(["rest", "servicedeskapi", "organization"])

        organizations = cls._get_paged_results(url.url)

        # Check if searching
        if name:

            # Find them
            return next((o for o in organizations if o["name"].lower() == name.lower()), None)

        else:

            return organizations

    @classmethod
    def get_organization_id(cls, name):
        """
        Returns a list of current organizations for the service desk. If passed,
        filters by name.

        :param email: The email of the customer to find, defaults to None
        :type email: str, optional
        """
        # Return it
        return cls.get_organization(name=name)["id"]

    @classmethod
    def get_customers(cls, email=None):
        """
        Returns a list of current customers for the service desk. If passed,
        filters by email address.

        :param email: The email of the customer to find, defaults to None
        :type email: str, optional
        """
        # Make the request
        url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
        url.path.segments.extend(["rest", "servicedeskapi", "servicedesk", dbmi_settings.JIRA_SERVICE_DESK, "customer"])

        customers = cls._get_paged_results(url.url)

        # Check if searching
        if email:

            # Find them
            return next((c for c in customers if c["emailAddress"].lower() == email.lower()), None)

        else:

            return customers

    @classmethod
    def get_customer_id(cls, email):
        """
        Returns the ID of the user for the passed email, or None if the
        customer does not exist.

        :param email: The email to search on
        :type email: str
        """
        # Get customers
        customer = cls.get_customers(email=email)
        if customer:

            return customer["accountId"]

        return None

    @classmethod
    def get_service_desks(cls):
        """
        Gets the service desks object from Jira
        """
        # Make the request
        url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
        url.path.segments.extend(["rest", "servicedeskapi", "servicedesk"])

        return cls._get_paged_results(url.url)

    @classmethod
    def get_service_desk_id(cls):
        """
        Gets the service desk ID from Jira
        """
        return next((s["id"] for s in cls.get_service_desks() if s["projectKey"] == dbmi_settings.JIRA_SERVICE_DESK), None)

    @classmethod
    def get_request_types(cls):
        """
        Gets the request types for the configured service desk from Jira
        """
        # Make the request
        url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
        url.path.segments.extend(["rest", "servicedeskapi", "servicedesk", dbmi_settings.JIRA_SERVICE_DESK, "requesttype"])

        return cls._get_paged_results(url.url)

    @classmethod
    def create_customer(cls, email, name):
        """
        Creates a customer in Jira Support Desk and returns their ID.

        :param email: The email of the user to create
        :type email: str
        :param name: The name of the customer to create
        :type name: str
        :return: A tuple of operation success and response data
        :rtype: boolean, object
        """
        content = None
        try:
            # Make the request
            url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
            url.path.segments.extend(["rest", "servicedeskapi", "customer"])

            # Set the data
            data = {
                "email": email,
                "fullName": name,
            }

            # Pull a page
            response = requests.post(url.url, json=data, headers=cls._headers(), auth=cls._auth())
            content = response.content
            response.raise_for_status()

            # Return ID
            return response.ok, response.json()

        except Exception as e:
            logger.exception(
                f"Support: Error creating Jira customer: {e}",
                exc_info=True,
                extra={
                    'email': email,
                    'response': response,
                }
            )

        return False, content

    @classmethod
    def add_customer_to_service_desk(cls, customer_id):
        """
        Adds a customer in Jira Support Desk to the configured
        service desk.

        :param customer_id: The ID of the user to add
        :type customer_id: str
        :return: A tuple of operation success and response data
        :rtype: boolean, object
        """
        content = None
        try:
            # Make the request /rest/servicedeskapi/servicedesk/{serviceDeskId}/customer
            url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
            url.path.segments.extend(["rest", "servicedeskapi", "servicedesk", dbmi_settings.JIRA_SERVICE_DESK, "customer"])

            # Set the data
            data = {"usernames":[customer_id]}

            # Pull a page
            response = requests.post(url.url, json=data, headers=cls._headers(), auth=cls._auth())
            content = response.content
            response.raise_for_status()

            # Return ID
            return response.ok, response.json()

        except Exception as e:
            logger.exception(
                f"Support: Error adding customer to service desk: {e}",
                exc_info=True,
                extra={
                    'customer_id': customer_id,
                    'response': response,
                }
            )

        return False, content

    @classmethod
    def add_customer_to_organization(cls, customer_id, organization_id):
        """
        Adds a customer in Jira Support Desk to the passed organization

        :param customer_id: The ID of the user to add
        :type customer_id: str
        :param organization_id: The ID of the organization
        :type organization_id: str
        :return: A tuple of operation success and response data
        :rtype: boolean, object
        """
        content = None
        try:
            # Make the request
            url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
            url.path.segments.extend(["rest", "servicedeskapi", "organization", organization_id, "user"])

            # Set the data
            data = {"usernames":[customer_id]}

            # Pull a page
            response = requests.post(url.url, json=data, headers=cls._headers(), auth=cls._auth())
            content = response.content
            response.raise_for_status()

            # Return ID
            return response.ok, response.json()

        except Exception as e:
            logger.exception(
                f"Support: Error adding customer to organization: {e}",
                exc_info=True,
                extra={
                    'customer_id': customer_id,
                    'organization_id': organization_id,
                    'response': response,
                }
            )

        return False, content

    @classmethod
    def create_request(cls, customer, request_type_id, subject, request, labels=None):
        """
        Creates a request for the passed customer.

        :param customer: The customer ID or email to create the request on behalf of
        :type customer: str
        :param request_type_id: The request type ID
        :type request_type_id: str
        :param subject: The subject of the request
        :type subject: str
        :param request: The body of the request
        :type request: str
        :return: Whether the request succeeded and the object
        :rtype: bool, dict
        """
        content = None
        try:
            # Get the service desk ID
            service_desk_id = cls.get_service_desk_id()

            # Make the request
            url = furl(f"https://{dbmi_settings.JIRA_ORGANIZATION}.atlassian.net")
            url.path.segments.extend(["rest", "servicedeskapi", "request"])

            # Set the data
            data = {
                "serviceDeskId": service_desk_id,
                "requestTypeId": request_type_id,
                "requestFieldValues": {
                    "summary": subject,
                    "description": request
                },
                "raiseOnBehalfOf": customer,
            }

            # Check for labels
            if labels and type(labels) is list:

                # Add them
                data["requestFieldValues"]["labels"] = labels

            # Pull a page
            response = requests.post(url.url, json=data, headers=cls._headers(), auth=cls._auth())
            content = response.content
            response.raise_for_status()

            # Return ID
            return response.ok, response.json()

        except Exception as e:
            logger.exception(
                f"Support: Error creating Jira request: {e}",
                exc_info=True,
                extra={
                    'customer': customer,
                    'request_type': request_type_id,
                    'labels': labels,
                    'response': response,
                }
            )

        return False, content

    @classmethod
    def email_request(cls, email, subject, message):
        """
        Emails a request on behalf of the user/customer

        :param email: The customer email to create the request on behalf of
        :type email: str
        :param subject: The subject of the request
        :type subject: str
        :param message: The body of the request
        :type message: str
        :return: Whether the request succeeded and the object
        :rtype: bool
        """
        # Check configs
        if not dbmi_settings.JIRA_SERVICE_DESK_EMAIL:
            raise SystemError(f"Cannot email without configured Jira service desk email")

        try:
            # Send it
            success = send_mail(
                subject=subject,
                message=message,
                from_email=email,
                recipient_list=[dbmi_settings.JIRA_SERVICE_DESK_EMAIL],
                fail_silently=False,
            )

            return success

        except Exception as e:
            logger.exception(
                f"Support: Error emailing Jira: {e}",
                exc_info=True,
            )

        return False
