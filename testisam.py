
import logging.config
import pprint
from ibmsecurity.appliance.isamappliance import ISAMAppliance
from ibmsecurity.user.applianceuser import ApplianceUser
from ibmsecurity.user.isamuser import ISAMUser
import pkgutil
import importlib
import yaml
import json


def import_submodules(package, recursive=True):
    """
    Import all submodules of a module, recursively, including subpackages

    :param package: package (name or actual module)
    :type package: str | module
    :rtype: dict[str, types.ModuleType]
    """
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        full_name = package.__name__ + '.' + name
        results[full_name] = importlib.import_module(full_name)
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results


import ibmsecurity

# Import all packages within ibmsecurity - recursively
# Note: Advisable to replace this code with specific imports for production code
import_submodules(ibmsecurity)

# Setup logging to send to stdout, format and set log level
# logging.getLogger(__name__).addHandler(logging.NullHandler())
logging.basicConfig()
# Valid values are 'DEBUG', 'INFO', 'ERROR', 'CRITICAL'
logLevel = 'INFO'
DEFAULT_LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '[%(asctime)s] [PID:%(process)d TID:%(thread)d] [%(levelname)s] [%(name)s] [%(funcName)s():%(lineno)s] %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': logLevel,
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'level': logLevel,
            'handlers': ['default'],
            'propagate': True
        },
        'requests.packages.urllib3.connectionpool': {
            'level': 'ERROR',
            'handlers': ['default'],
            'propagate': True
        }
    }
}
logging.config.dictConfig(DEFAULT_LOGGING)


# Function to pretty print JSON data and in YAML format
def p(jdata):
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(jdata)
    #print(yaml.safe_dump(jdata, encoding='utf-8', allow_unicode=True))


# Create a user credential for ISAM appliance
u = ApplianceUser(username="admin@local", password="kiss2015")
# Create an ISAM appliance with above credential
isam_server = ISAMAppliance(hostname="192.168.1.195", user=u, lmi_port=443)

# Get the current SNMP monitoring setup details
#ibmsecurity.isam.base.snmp_monitoring.get(isamAppliance=isam_server)
#p(ibmsecurity.isam.base.snmp_monitoring.get(isamAppliance=isam_server))
# Set the V2 SNMP monitoring
#ibmsecurity.isam.base.snmp_monitoring.set_v1v2(isamAppliance=isam_server, community="IBM")
p(ibmsecurity.isam.base.network.packettrace.get(isamAppliance=isam_server))
#p(ibmsecurity.isam.base.network.packettrace.execute(isamAppliance=isam_server,operation="start",enabled="true"))
#p(ibmsecurity.isam.base.network.packettrace.execute(isamAppliance=isam_server,operation="stop",enabled="false"))
p(ibmsecurity.isam.base.network.packettrace.delete(isamAppliance=isam_server))


# Commit or Deploy the changes
p(ibmsecurity.isam.appliance.commit(isamAppliance=isam_server))