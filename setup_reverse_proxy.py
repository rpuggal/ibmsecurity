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
    """ Import all submodules of a module, recursively, including subpackages

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

# Import all packages within ibmsecurity!!!
import_submodules(ibmsecurity)

# logging.getLogger(__name__).addHandler(logging.NullHandler())
logging.basicConfig()
# Setup logging to send to stdout, format and set log level
logLevel = 'DEBUG'
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

def p(jdata):
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(jdata)
    print(yaml.safe_dump(jdata, encoding='utf-8', allow_unicode=True))

ip=raw_input("Please enter the IP address or hostname of the ISAM appliance:")
pwd=raw_input("Please enter the password for the ISAM appliance user:")
u = ApplianceUser(username="admin@local", password=pwd)
isam9_server3 = ISAMAppliance(ip, u)

################ PRODUCT ACTIVATION ################
# print isam.base.activation.set(isam9_server2, code="9A08-84CC-599A-5CC2-C4D9-ACD3-AD70-B4D6", id="federation")

################ LMI APPLIANCE PASSWORD CHANGE ################
#p(ibmsecurity.isam.base.admin.get(isamAppliance=isam9_server3))
#newpwd=raw_input("Please enter the new password for the ISAM appliance user:")
#p(ibmsecurity.isam.base.admin.set_pw(isamAppliance=isam9_server3, oldPassword=pwd, newPassword=newpwd))

################ NETWORK TIME PROTOCOL ################
#print ibmsecurity.isam.base.date_time.get(isam9_server3)
#print ibmsecurity.isam.base.date_time.set(isam9_server3, ntpServers="9.55.253.49")

################ CHANGING HOST RECORDS ################
#print ibmsecurity.isam.base.host_records.get(isam9_server3)
#p(ibmsecurity.isam.base.host_records.set(isamAppliance=isam9_server3, hostname="www.isam.isslab.usga.ibm.com", ip_addr="9.55.253.83"))

################ DNS SETTINGS ################
#p(ibmsecurity.isam.base.network.dns.set(isam9_server3, auto=True, primaryServer='9.55.253.49', secondaryServer=None, tertiaryServer=None, searchDomains='isslab.usga.ibm.com'))
#p(ibmsecurity.isam.base.network.dns.get(isam9_server3))

################ CREATING ISAM RUNTIME INTERFACE ################
#p(ibmsecurity.isam.base.network.interfaces_ipv4.add(isamAppliance=isam9_server3, label='1.1', vlanId=None, address='9.55.253.83', maskOrPrefix='24'))

################ CONFIGURING THE RUNTIME COMPONENTS ################
# p(ibmsecurity.isam.web.runtime.process.get(isam9_server3))
p(isam.web.runtime.process.config(isam9_server3, admin_pwd='Passw0rd',ldap_pwd='passw0rd'))

################ CREATING A REVERSE PROXY INSTANCE ################
#p(ibmsecurity.isam.web.reverse_proxy.instance.get(isam9_server3))

#rp_name=raw_input("Reverse Proxy Instance Name:")
#host_name=raw_input("Reverse proxy hostname:")
#rp_ip=raw_input("IP Address for the primary interface")
#p(ibmsecurity.isam.web.reverse_proxy.instance.add(isam9_server3,inst_name=rp_name, admin_pwd= "Passw0rd", host=host_name, ip_address=rp_ip))

################ CREATING A JUNCTION ################
#jn_pointname=raw_input("please provide a junction point name:")
#server_hn=raw_input("Please provide the web server hostname:")
#p(ibmsecurity.isam.web.reverse_proxy.junctions.add(isamAppliance=isam9_server3, reverseproxy_id='default', junction_type='tcp', junction_point=jn_pointname, server_hostname=server_hn, server_port=80,force=True ))


################ CONFIGURING WEB APPLICATION FIREWALL ################

################ Enable web content protection check box to turn on the web application firewall ################
#p(ibmsecurity.isam.web.reverse_proxy.configuration.entry.update(isamAppliance=isam9_server3, reverseproxy_id='default', stanza_id='PAM',entry_id='pam-enabled', value_id='true' ))

################ Adding entries to the PAM Stanza ################
#p(ibmsecurity.isam.web.reverse_proxy.configuration.entry.add(isamAppliance=isam9_server3, reverseproxy_id='default', stanza_id='PAM',entries=[['pam-http-parameter', 'pam.injection.argument.token.limit:8'],['pam-resource-rule', '+index.html']]))


################ GET THE SNAPSHOTS ################
#p(ibmsecurity.isam.base.snapshots.get(isamAppliance=isam9_server3))

################ COMMIT THE CHANGES IN THE ISAM APPLIANCE ################
#p(ibmsecurity.isam.appliance.commit(isamAppliance=isam9_server3))


################ REBOOT THE ISAM APPLIANCE ################
#print ibmsecurity.isam.base.appliance.reboot(isam9_server3) Not working

################ SHUTDOWN THE ISAM APPLIANCE ################
#print ibmsecurity.isam.base.appliance.shutdown(isam9_server3) Not tested
