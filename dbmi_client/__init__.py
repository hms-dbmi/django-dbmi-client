"""
DBMI Client
"""

__title__ = "DBMI Client"
__version__ = "1.0.2"
__author__ = "Bryan Larson"
__license__ = "BSD 2-Clause"
__copyright__ = "Copyright 2011-2020 Harvard Medical School Department of Biomedical Informatics"

# Version synonym
VERSION = __version__

# Header encoding (see RFC5987)
HTTP_HEADER_ENCODING = "iso-8859-1"

# Default datetime input and output formats
ISO_8601 = "iso-8601"

default_app_config = "dbmi_client.apps.DBMIClientConfig"
