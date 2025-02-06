import datetime
import re
import time
import os
import polling
from ats import aetest
import logging
from threading import Thread
from lib.models.deploy.configrollback.model import RollbackRequest
from lib.models.deploy.model import DeploymentRequest
from lib.models.deploy.pendingchanges.model import PendingChanges
from lib.models.devices.device_management.device.inline_sets.inline_set.model import InlineSet
from lib.models.devices.device_management.high_availability.constants import UpdateHAActions
from lib.models.devices.device_management.high_availability.model import HighAvailability
from lib.models.devices.device_management.device.interfaces.physical_interface.model import PhysicalInterface
from lib.models.devices.ftdnat.model import FtdNatPolicy
from lib.models.devices.platform_settings.model import PlatformSettingsPolicy
from lib.models.fragments.advanced_access_policy.encrypted_visibility_engine.model import \
    EncryptedVisibilityEngineFragment
from lib.models.fragments.advanced_access_policy.eve_exception_rulelist_settings.model import \
    EveExceptionRuleListFragment
from lib.models.fragments.advanced_access_policy.model import AdvancedAccessPolicyFragment
from lib.models.fragments.inline_pairs.model import InlinePairsFragment
from lib.models.fragments.rules.dynamic_objects.model import RuleDynamicObjectFragment
from lib.models.objects.dynamic_objects.mappings.model import DynamicObjectMapping
from lib.models.objects.dynamic_objects.model import DynamicObject
from lib.models.objects.network.network_object.model import NetworkObject
from lib.models.policies.access_control.access_control.access_policy.access_rule.model import AccessRule
from lib.models.policies.access_control.access_control.access_policy.model import AccessPolicy
from lib.services.system.tools.backup_restore import BackupRestore, BackupOptions

from tests.feature.ftd.tests.DAQ.Defect_Automation.Test_Cases.DAQ_5.DAQ5_utils import DAQ5_utility
import fmc as fmc_mod_own
import yaml
from lib.common_modules.cli_connection import get_cli_connection
from lib.constants import TestBedConstants
from lib.models.devices.device_management.device.model import Device
from lib.models.policies.access_control.access_control.access_policy.policy_assignment.model import PolicyAssignment
from lib.services.api_service import APIService
import lib.commons.commons as ftltest
from lib.services.data.store import store
from lib.services.config_provider import ConfigProvider
from tests.feature.fmc.devices.device_management.device.high_availability.ftdha_Utility import Utility
from tests.feature.fmc.policies.intrusion.snort3_intrusion.snort3_intrusion_utility import Snort3Utility
from tests.feature.ftd.tests.EVE.EVE_utils import EVE_utils
from pathlib import Path
import tests.feature.ngfw.Snort.tests.unified_automation_snort_teacats_724.unified_automation_utility as vdb_utils
from lib.features_constants import Features76, Features77
from lib.utils.functions import set_testcase_feature, set_tims_testcase
from tests.feature.ftd.tests.EVE.Mitre_Test import CommonEve

DATA_PATH = 'data/EVE_Exclusion_list_HA_FQDN_data.yaml'
base_dir = os.path.dirname(__file__)
test_file_path = ["{}/{}".format(base_dir, DATA_PATH), __file__]
EVE_test_cases_data = yaml.safe_load(Path(test_file_path[0]).read_text())
EVE_test = EVE_test_cases_data['EVE_test_cases']
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


import argparse

parser = argparse.ArgumentParser(description="EVE Precommit")
parser.add_argument('--precommit', default=False)
args = parser.parse_known_args()[0]
precommit = args.precommit
if precommit == 'True':
    EVE_test = EVE_test_cases_data['EVE_precommit_test_cases']
else:
    EVE_test = EVE_test_cases_data['EVE_test_cases']

def break_high_availability():
    check_ha = ftd1_ssh.conn.execute('show failover')
    if "Failover On" in check_ha:
        log.info('HA is formed, perform failover state check')
        prim_active = ftd1_ssh.conn.execute('show failover | grep This')

        if "Active" in prim_active:
            log.info("Primary unit is Active unit, continue test")
        else:
            log.info("Switching Primary as Active unit")
            utility_object.ftdha_switch(fmc_API, ftd1_ssh, ftd2_ssh, ftdha_ipv4)

        ftdha_to_break = fmc_API.find_one(HighAvailability,
                                          lambda ftdha_object: ftdha_object.name == ftdha_ipv4.name)
        ftdha_to_break.action = UpdateHAActions.breakHA.value
        ftdha_to_break._polling_max_timeout = 700
        ftdha_to_break.forceBreak = 'true'  # for Force Break, this key is set to true

        fmc_API.update(ftdha_to_break)
        # added polling before assert because FTD-HA object is still present for another few seconds
        # although Break HA completes with success
        polling.poll(
            lambda: fmc_API.find_one(HighAvailability,
                                     lambda ftdha_object: ftdha_object.name == ftdha_ipv4.name) is None,
            step=15,
            timeout=700
        )
        broken_ftdha = fmc_API.find_one(HighAvailability, lambda ftdha_object: ftdha_object.name == ftdha_ipv4.name)
        assert broken_ftdha is None

        # Validate Deploy List is Empty
        deployment_to_check = DeploymentRequest()
        assert len(deployment_to_check.deviceList) == 0
    else:
        log.info('HA is not formed, do not perform break')


class CommonSetup(ftltest.CommonSetup):
    @aetest.subsection
    def set_up(self, testbed, api_service_fmc1: APIService):
        global ftd_type
        global ftd1_ssh
        global ftd2_ssh
        global ftdha_ipv4
        global fmc_API
        global spin_lock
        fmc_API = api_service_fmc1
        log.info(f'we are in Common_SET_UP function\n\n')
        dir = os.path.dirname(os.path.realpath(__file__))
        print(dir)
        store.set_data_folder(dir)
        print("base directory is", dir)
        self.args.data_file.extend(["{}/{}".format(dir, DATA_PATH), __file__])
        print("the file paths after extension", self.args.data_file)
        device_ip = testbed.devices[TestBedConstants.sensor1.value].interfaces["management1"].ipv4.ip.compressed
        print(device_ip)
        device = api_service_fmc1.find_one(Device, condition=lambda device_obj: device_obj.hostName == device_ip)
        self.parent.parameters.update({'fmc_config_provider': self.parent.parameters[self.args.fmc_alias]})
        # endpoint1_wget_ip = testbed.devices["endpoint1"].interfaces["eth3"].ipv4.ip.compressed
        # endpoint2_wget_ip = testbed.devices["endpoint2"].interfaces["eth3"].ipv4.ip.compressed
        fmc = self.parent.parameters[self.args.fmc_alias]
        interface_alias = {"management1"}
        if interface_alias.issubset(testbed.devices[TestBedConstants.fmc1.value].interfaces.aliases):
            fmc_ip = str(fmc.device.interfaces["management1"].ipv4.ip)
        else:
            fmc_ip = str(fmc.device.connections.management.ip)
        # utility_object1 = MacAddressUtility()

        log.info('\nConnecting Endpoint1')
        endpoint1_ip = ConfigProvider(testbed, TestBedConstants.endpoint1.value)
        endpoint1 = endpoint1_ip.get_ssh_connection()
        endpoint2_ip = ConfigProvider(testbed, TestBedConstants.endpoint2.value)
        endpoint2 = endpoint2_ip.get_ssh_connection()

        # inside_interface_ip = EVE_test_cases_data["ipv4_static.int_ipv4_static_config0"]["address"]
        # outside_interface_ip = EVE_test_cases_data["ipv4_static.int_ipv4_static_config1"]["address"]
        ftd1 = ConfigProvider(testbed, TestBedConstants.sensor1.value)
        ftd1_cli = get_cli_connection(testbed, device_label="sensor1")
        ftd2 = ConfigProvider(testbed, TestBedConstants.sensor2.value)
        ftd2_cli = get_cli_connection(testbed, device_label="sensor2")
        ftd_type = "ftd_type"

        ftd1_ip = str(testbed.devices[TestBedConstants.sensor1.value].interfaces["management1"].ipv4.ip)
        ftd1_config = api_service_fmc1.find_one(Device, lambda obj: obj.name == ftd1_ip)

        ftd1_cli.go_to('sudo_state')
        ftd1_cli.sendline("echo "" > /ngfw/var/log/messages")
        # ftd1_cli.execute('echo \"\" > /ngfw/var/log/messages')

        primary_fmc = ConfigProvider(testbed, TestBedConstants.fmc1.value)
        fmc_ssh = primary_fmc.get_ssh_connection()

        global utility_object
        utility_object = Utility()
        snort3_utility_object = Snort3Utility()
        utility_eve = EVE_utils()

        os.environ['SNORT3'] = 'True'
        ftd1_ssh = ftd1.get_ssh_connection()
        ftd1_major_version = DAQ5_utility.Find_FTD_Major_Version(self, ftd1_ssh)
        ftd2_ssh = ftd2.get_ssh_connection()

        ftd2_major_version = DAQ5_utility.Find_FTD_Major_Version(self, ftd1_ssh)
        ftdha_ipv4 = store.get("file:{}".format(self.args.data_file[0]),
                               root_object='ftd_ha.ftdha_global_domain')
        print(f'\n\n\nFTD1 Version is {ftd1_major_version}\n\n\n\n')
        print(f'\n\n\nFTD2 Version is {ftd2_major_version}\n\n\n\n')
        fmc_obj = fmc_mod_own.FMC(name=testbed.devices[TestBedConstants.fmc1.value].custom.hostname,
                                  ip=testbed.devices[TestBedConstants.fmc1.value].connections.management.ip,
                                  ssh_port=testbed.devices[TestBedConstants.fmc1.value].connections.management.port,
                                  http_port=testbed.devices[TestBedConstants.fmc1.value].connections.web.port,
                                  passwd=testbed.devices[TestBedConstants.fmc1.value].connections.management.password)

        fmc_obj.restapi_setuser(user='restadmin', password='Admin123')
        fmc_obj.connect()
        fmc_obj.get_domain_uuid()

        found_first_inline_interface = api_service_fmc1.find_one(
            PhysicalInterface,
            lambda obj: obj.name == testbed.devices[TestBedConstants.sensor1.value].interfaces[
                'traffic1'].name,
            container_id=device.id)

        found_second_inline_interface = api_service_fmc1.find_one(
            PhysicalInterface,
            lambda obj: obj.name == testbed.devices[TestBedConstants.sensor1.value].interfaces[
                'traffic2'].name,
            container_id=device.id)

        cmd = "cd /etc/bind"
        endpoint2.conn.execute(cmd, timeout=2)
        cmd = "mv /etc/bind/named.eve.com old_file_eve"
        endpoint2.conn.execute(cmd, timeout=2)
        cmd = "mv /etc/bind/named.conf.local old_file_eve_local"
        endpoint2.conn.execute(cmd, timeout=2)
        ep_path = "/etc/bind"


        path1 = base_dir+"/data/named.conf.local.txt"
        log.info(path1)
        log.info("*******************************************************************************************************")
        log.info("copying configure file from {} to device {}".format(path1, ep_path))
        # endpoint2.conn.execute("mkdir -p {}".format(ep_path))
        endpoint2.copy_from_container_to_device(path1, ep_path)

        path2 = base_dir+"/data/named.eve.com.txt"
        log.info(path2)
        log.info("copying configure file from {} to device {}".format(path2, ep_path))
        # endpoint2.conn.execute("mkdir -p {}".format(ep_path))
        endpoint2.copy_from_container_to_device(path2, ep_path)
        cmd1 = "mv named.conf.local.txt named.conf.local"
        endpoint2.conn.execute(cmd1, timeout=5)
        cmd2 = "mv named.eve.com.txt named.eve.com"
        endpoint2.conn.execute(cmd2, timeout=10)

        outside_host_ip = str(testbed.devices[TestBedConstants.endpoint2.value].interfaces["traffic1"].ipv4.ip)
        inside_host_ip = str(testbed.devices[TestBedConstants.endpoint1.value].interfaces["traffic1"].ipv4.ip)
        dns_server_ip = str(testbed.devices[TestBedConstants.endpoint2.value].interfaces["traffic3"].ipv4.ip)

        cmd = "sed -i 's/1.1.1.1/{}/g' /etc/bind/named.eve.com".format(outside_host_ip)
        endpoint2.conn.execute(cmd, timeout=2)
        log.info("updating dns and search domain in EP2")
        cmd = "echo nameserver {} > /etc/resolv.conf".format(dns_server_ip)
        cmd1 = "echo search eve.com >> /etc/resolv.conf"
        result = endpoint2.conn.execute(cmd, timeout=20)
        result = endpoint2.conn.execute(cmd1, timeout=20)

        result = endpoint2.conn.execute(cmd="cat /etc/resolv.conf", timeout=20)
        cmd = 'systemctl restart named'
        endpoint2.conn.execute(cmd, timeout=5)

        # security_zone = store.get("file:{}".format(self.args.data_file[0]),
        #                           root_object='security_zones.subint_security_zones{}'.format(1))
        ps_policy_config = store.get("file:{}".format(self.args.data_file[0]),
                                     root_object='platform_settings_policy.create')

        ps_policy_config.dns.MultiDNSServerGroupsTable[0].MultiDnsServerGroupName.dnsservers = [dns_server_ip]
        # ps_policy_config.dns.FTDDnsDomainLookupInterface[0].name = security_zone.name
        required_interface = ''
        client_ip_address = str(testbed.devices[TestBedConstants.endpoint2.value].interfaces.eth1.ipv4.ip)
        server_ip_address = str(testbed.devices[TestBedConstants.endpoint1.value].interfaces.eth1.ipv4.ip)
        available_interface = testbed.devices[TestBedConstants.endpoint2.value].interfaces.eth1.mode
        if available_interface == "inline":
            required_interface = 'eth1'

        self.parent.parameters.update({
            'inlineset_config': store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='inline_set.test_rest_inlineset'),
            "EVE_exempt_fqdnv4_policy__no_dns_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="access_policies.EVE_exempt_fqdnv4_policy_no_dns"),
            "EVE_exempt_fqdnv4_policy_invalid_domain_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="access_policies.EVE_exempt_fqdnv4_policy_invalid_domain"),
            "EVE_exempt_fqdnv4_policy_dns_not_reachable_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="access_policies.EVE_exempt_fqdnv4_policy_not_reachable"),
            "EVE_exempt_fqdnv4_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="access_policies.EVE_exempt_fqdnv4_policy"),
            "EVE_exempt_fqdnv6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="access_policies.EVE_exempt_fqdnv6_policy"),
            "EVE_exempt_fqdnv4v6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="access_policies.EVE_exempt_fqdnv4v6_policy"),
            "EVE_exempt_with_ssl_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_fqdn_ssl_policy'),
            "EVE_exempt_with_ssl_policy_quic_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_fqdn_quic_policy'),
            "EVE_exempt_with_ssl_policy_tsid_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_fqdn_tsid_policy'),
            "nat_fqdn_ac_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.nat_Ac_Policy'),
            "nat_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='nat_policies.natpolicy_with_nat_rules'),
            "vdb_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.vdb_Ac_Policy'),
            "fqdn_unique_object_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.fqdn_unique_object_AC_policy'),
            "fqdn_common_object_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.fqdn_common_object_AC_policy'),
            "fqdn_unresolved_ip_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_fqdnv4_unresolved_ip'),
            "fqdn_clear_cache_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_fqdnv4_clear cache'),
            "fqdn_live_traffic_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_fqdnv4_policy_live_traffic'),
            "EVE_fqdn_process_name_change": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_fqdn_process_name_change'),
            "Network_object_fqdnv4": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='networks.dest_fqdn_host_object_name_change'),
            'child_access_policy': store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.child_policy'),
            "inheritance_network_obj": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='networks.dest_inheritance_host_object'),
            "dyn_attr_AC_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_dyn_attr_AC_policy'),
            "fqdn_AC_policy_clone_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_fqdn_clone_policy'),
            "dyn_attr_AC_policy_remove_map_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_dyn_attr_remove_mapping'),
            "EVE_exempt_import_export_policy_config":store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_import_export'),
            "dyn_attr_AC_policy_common_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.Dynamic_attri_AC_policy_common'),
            "dynamic_object_data_common_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='dynamic_object.common_da'),
            "ac_rule_with_dynamic_object_common_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_rules.common_dynamic'),
            "dyn_attr_AC_policy_unique_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.Dynamic_attri_AC_policy_unique'),
            "ac_rule_with_dynamic_object_unique": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_rules.unique_dynamic'),
            "dynamic_object_data_unique": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='dynamic_object.dynamic_v4'),
            "Dyn_attri_update_AC_policy_v4_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.Dynamic_attri_AC_policy_update'),
            "dynamic_object_data_update": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='dynamic_object.update_da'),
            "ac_policy_dynamic_fqdn_switchover_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_fqdnv4_switch_over'),
            "EVE_exempt_Backup_Restore_fqdnv4v6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="access_policies.Backup_Restore_EVE_exempt_fqdnv4v6_policy"),
            "Dyn_attri_bulk_ip_AC_policy_v4_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.Dynamic_attri_AC_policy_bulk_ip_mapping'),
            "deployment_rollback_AC_policy_v4_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.roll_back'),
            "new_ex_rule": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object="eve_exception_rule_list.rollback_rule"),
            "roll_host_object": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='networks.roll_host_object'),
            "ac_policy_bulk_exception_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='access_policies.EVE_exempt_bulk_exception_rule'),
            "EVE_valid_exception_rule_config": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='eve_exception_rule_list.eveExceptionRulefqdnv4object'),
            "EVE_exception_mercury_stats_config": store.get("file:{}".format(self.args.data_file[0]),
                                                         root_object='access_policies.EVE_exempt_with_mercury_stats'),
            "EVE_exception_mercury_module_config": store.get("file:{}".format(self.args.data_file[0]),
                                                            root_object='access_policies.EVE_exempt_mercury_module'),
            "EVE_exception_mercury_dashboard_config": store.get("file:{}".format(self.args.data_file[0]),
                                                             root_object='access_policies.EVE_exception_mercury_dashboard_config'),

            "data_purge": store.get("file:{}".format(self.args.data_file[0]),
                                                     root_object='purge.data_purge'),
            "device": device,
            "testbed": testbed,
            "yaml_data": self.args.data_file[0],
            'utility': utility_object,
            'snort3_utility': snort3_utility_object,
            'utility_eve': utility_eve,
            'ftd1_cli': ftd1_cli,
            'ftd2_cli': ftd2_cli,
            'ftd1': ftd1,
            'ftd2': ftd2,
            'ftd1_ssh': ftd1_ssh,
            'ftd2_ssh': ftd2_ssh,
            'fmc_obj': fmc_obj,
            'spin_lock': False,
            'ftd1_major_version': ftd1_major_version,
            'ftd2_major_version': ftd2_major_version,
            "fmc_ssh": fmc_ssh,
            # 'utility1': utility_object1,
            'fmc_ip': fmc_ip,
            'primary_fmc': primary_fmc,
            'ftdha_ipv4': ftdha_ipv4,
            'ha_name': "HA-Global-Domain",
            'endpoint1_name': "endpoint1",
            'endpoint2_name': "endpoint2",
            'endpoint1_ssh': endpoint1,
            'endpoint2_ssh': endpoint2,
            "first_inline_interface": found_first_inline_interface,
            "second_inline_interface": found_second_inline_interface,
            "ps_policy_config": ps_policy_config,
            "ftd1_config": ftd1_config,
            "base_dir": base_dir,
            "client_ip_address": client_ip_address,
            "server_ip_address": server_ip_address,
            "required_interface": required_interface
        })

    @aetest.subsection
    def creating_physical_inline_interface(self, api_service_fmc1, first_inline_interface, second_inline_interface,
                                           device: Device):
        first_inline_interface.ifname = "interface1inline"
        first_inline_interface.MTU = 1500
        first_inline_interface.enabled = True

        second_inline_interface.ifname = "interface2inline"
        second_inline_interface.MTU = 1500
        second_inline_interface.enabled = True

        api_service_fmc1.update(first_inline_interface, container_id=device.id)
        api_service_fmc1.update(second_inline_interface, container_id=device.id)

    @aetest.subsection
    def create_inlineset(self, api_service_fmc1: APIService, inlineset_config: InlineSet,
                         device: Device, first_inline_interface: PhysicalInterface, second_inline_interface: PhysicalInterface):
        inlineset_config.interfaces = [
            InlinePairsFragment(**{
                'first': first_inline_interface,
                'second': second_inline_interface
            })
        ]
        inlineset = api_service_fmc1.create(inlineset_config, container_id=device.id)
        created_inlineset = api_service_fmc1.find_one(
            InlineSet,
            lambda inline_set: inline_set.name == inlineset.name,
            container_id=device.id)
        assert inlineset.name == created_inlineset.name
        assert inlineset.mtu == created_inlineset.mtu

        deployment_request = DeploymentRequest()
        # Adding device, which contains the ac_policy added before to the deployment request object
        deployment_request.deviceList.append(device)
        # Creates the deployment request on the device
        api_service_fmc1.create(deployment_request)
        self.parent.parameters.update(deployment=deployment_request, inlineset=inlineset)

    @aetest.subsection
    def deploy_after_switch_pa_ss(self, api_service_fmc1: APIService, ftd1_ssh, ftd2_ssh):

        log.info('\nDeploying the changes to FTDHA pair\n')

        primary_device = api_service_fmc1.find_one(Device,
                                                   condition=lambda
                                                       device_obj: device_obj.name == ftd1_ssh.device_ip)
        secondary_device = api_service_fmc1.find_one(Device,
                                                     condition=lambda
                                                         device_obj: device_obj.name == ftd2_ssh.device_ip)

        log.info('\nInitiating the Deploy to the Primary Device\n')
        deployment_to_create = DeploymentRequest()
        log.info("FTD 1 Deploy status : " + str(primary_device.deploymentStatus))
        log.info("FTD 2 Deploy status : " + str(secondary_device.deploymentStatus))
        if primary_device.deploymentStatus == "DEPLOYMENT_PENDING":
            deployment_to_create.deviceList.append(primary_device)
            log.info("Added FTD 1")

        if secondary_device.deploymentStatus == "DEPLOYMENT_PENDING":
            deployment_to_create.deviceList.append(secondary_device)
            log.info("Added FTD 2")

        log.info('\nCreates the deployment request on the device\n')
        if len(deployment_to_create.deviceList):
            api_service_fmc1.create(deployment_to_create)

    @aetest.subsection
    def create_high_availability(self, api_service_fmc1: APIService, testbed, ftd1_ssh, ftd2_ssh, ftdha_ipv4, utility,
                                 utility_eve):
        utility_eve.create_high_availability(api_service_fmc1, testbed, ftd1_ssh, ftd2_ssh, ftdha_ipv4, utility)


    @aetest.subsection
    def clone_pcap_files(self):
        try:
            log.info("Cloning Pcaps Repository in Test Case Directory")
            os.system("rm -rf {}/eve_test_pcaps".format(base_dir))
            os.chdir("{}".format(base_dir))
            os.system("git clone {0} -b {1}".format(EVE_test_cases_data['git_info']['clone_url'],
                                                    EVE_test_cases_data['git_info']['clone_branch']))
        except Exception as e:
            log.error("Failed to Clone Pcap Files: {}".format(e))


@aetest.loop(FQDN_test_case=list(EVE_test.keys()))
class FQDN_Testcases(aetest.Testcase):
    @aetest.setup
    def set_feature(self):
        set_testcase_feature([Features77.feature73.value])
        set_tims_testcase("Txw16380309c, Txw16380310c, Txw16187115c, Txw16369695c, Txw16369705c,Txw16380314c,Txw16380326c, Txw16380327c, Txw16380357c, Txw16369706c, Txw16179316c,Txw16179328c,Txw16369707c")

    @aetest.test
    def eve_test_cases(self, steps, FQDN_test_case, utility, api_service_fmc1, utility_eve, ftd1_ssh, ftd2_ssh, fmc1,ftd1,
                       testbed, device, ftd1_cli, ftd2_cli, endpoint1_ssh, endpoint2_ssh, data_purge, EVE_exempt_with_ssl_policy_config, EVE_exempt_fqdnv4_policy_config,
                       EVE_exempt_fqdnv6_policy_config, EVE_exempt_fqdnv4v6_policy_config,nat_policy_config,nat_fqdn_ac_policy_config,
                       vdb_access_policy_config,fqdn_unique_object_access_policy_config,fqdn_common_object_access_policy_config,ps_policy_config: PlatformSettingsPolicy,
                       ftd1_config: Device,EVE_exempt_fqdnv4_policy__no_dns_config,EVE_exempt_fqdnv4_policy_invalid_domain_config,EVE_exempt_fqdnv4_policy_dns_not_reachable_config,
                       fqdn_unresolved_ip_access_policy_config,fqdn_clear_cache_access_policy_config,fqdn_live_traffic_access_policy_config,EVE_fqdn_process_name_change,Network_object_fqdnv4,
                       EVE_exempt_with_ssl_policy_quic_config,EVE_exempt_with_ssl_policy_tsid_config,dyn_attr_AC_policy_config,fqdn_AC_policy_clone_config,dyn_attr_AC_policy_remove_map_config,
                       child_access_policy,inheritance_network_obj,EVE_exempt_import_export_policy_config,dyn_attr_AC_policy_common_config,dynamic_object_data_common_config,
                       ac_rule_with_dynamic_object_common_config:AccessRule,dyn_attr_AC_policy_unique_config,ac_rule_with_dynamic_object_unique:AccessRule,dynamic_object_data_unique,
                       Dyn_attri_update_AC_policy_v4_config,dynamic_object_data_update,ac_policy_dynamic_fqdn_switchover_config,EVE_exempt_Backup_Restore_fqdnv4v6_policy_config,
                       Dyn_attri_bulk_ip_AC_policy_v4_config,new_ex_rule,roll_host_object,deployment_rollback_AC_policy_v4_config,ac_policy_bulk_exception_config,EVE_valid_exception_rule_config,
                       EVE_exception_mercury_stats_config,EVE_exception_mercury_module_config,EVE_exception_mercury_dashboard_config,base_dir,client_ip_address,server_ip_address,required_interface):

        sec = 120
        time.sleep(sec)
        FQDN_test_name = EVE_test[FQDN_test_case]
        log.info("********** {}".format(FQDN_test_name))
        hostname = FQDN_test_name['dns_name']
        ip_addr = FQDN_test_name['address']
        bakup_time=600


        if "Exception_with_Destination_FQDN_V4_without_DNS" == FQDN_test_case:
            log.info("Starting the test cases")
            log.info("Testcase: {}".format(FQDN_test_case))

            with steps.start("Returning back from the sudo user"):
                ftd1_ssh.conn.go_to('fireos_state')
                ftd1_ssh.conn.execute("show snort counters")

            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_fqdnv4_policy__no_dns_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    log.info("DNS Host check failed due to DNS server not configured")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is not increased for eve exempt due to DNS server not configured"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to not Configuring DNS server")

            with steps.start("Verifying  of unified events in FMC is getting failed due to DNS server not configured"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to not Configuring DNS server")

        elif "Exception_with_Destination_FQDN_V4" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))

            with steps.start("creating platform settings policy"):
                created_ps_policy = api_service_fmc1.create(ps_policy_config)
                assert created_ps_policy.identifier
                found_ps_policy = api_service_fmc1.find_one_by_record(created_ps_policy)
                assert found_ps_policy.name == created_ps_policy.name
                assert found_ps_policy.description == created_ps_policy.description
                assert found_ps_policy.validateOnly == created_ps_policy.validateOnly
                assert found_ps_policy.identifier == created_ps_policy.identifier
                self.parent.parameters.update(created_ps_policy=created_ps_policy)

            with steps.start("Assigning platform policy to ftd"):
                policy_assignment = PolicyAssignment()
                policy_assignment.api = "csm"
                policy_assignment.targets = [ftd1_config]
                policy_assignment.policy = created_ps_policy
                api_service_fmc1.create(policy_assignment)
                self.parent.parameters.update(existing_assignment=policy_assignment)
            time.sleep(15)

            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_fqdnv4_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            time.sleep(10)
            with steps.start("Checking DNS Host Address"):
                ftd1_ssh = ftd1.get_ssh_connection()
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_invalid_domain" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_fqdnv4_policy_invalid_domain_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    log.info("Unable to resolve DNS due to invalid domain name")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is not increased for eve exempt due to invalid domain"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to invalid domain name")

            with steps.start("Verifying unified events in FMC is getting failed due to invalid domain"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to invalid domain")

        elif "Exception_with_Destination_FQDN_dns_not_reachable" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_fqdnv4_policy_dns_not_reachable_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Deactivating the DNS server"):
                endpoint2_ip = ConfigProvider(testbed, TestBedConstants.endpoint2.value)
                endpoint2_ssh = endpoint2_ip.get_ssh_connection()
                endpoint2_ssh.conn.execute("systemctl stop named")
                time.sleep(15)
                res = endpoint2_ssh.conn.execute("systemctl status named")
                if "Stopped BIND Domain Name Server" in res:
                    log.info("DNS server Deactivated successfully")

            with steps.start("Checking DNS Host Address"):
                time.sleep(5)
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    log.info("ERROR: DNS server not reachable")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is not increased for eve exempt due to DNS server not reachable"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to DNS server not reachable")

            with steps.start("Verifying unified events in FMC is getting failed due to DNS server not reachable"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to DNS server not reachable")

            with steps.start("Activating the DNS server"):
                endpoint2_ssh.conn.execute("systemctl start named")
                time.sleep(15)
                res = endpoint2_ssh.conn.execute("systemctl status named")
                if "Started BIND Domain Name Server" in res:
                    log.info("DNS server Activated successfully")

        elif "Exception_with_Destination_FQDN_V6" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_fqdnv6_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC fa iled")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_V4_V6" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_fqdnv4v6_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_V4_ssl" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_with_ssl_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

                # CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh,
                #                     data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_V4_quic" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_with_ssl_policy_quic_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                # utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
                CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh,
                                        data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_V4_tsid" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_with_ssl_policy_tsid_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            # with steps.start("Running the traffic using Aquila-Replay in client and server"):
            #     pcap_path = "eve_test_pcaps"
            #     pcap = FQDN_test_name['pcap_file']
            #     EVE_utils().Aquila_replay(ftd1_ssh,endpoint1_ssh,endpoint2_ssh,api_service_fmc1, data_purge,base_dir, pcap_path,pcap,client_ip_address,server_ip_address,required_interface)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_nat" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))

            with steps.start("Create NAT policy"):
                api_service_fmc1.create(nat_policy_config, container_id=device.id)
                nat_policy = api_service_fmc1.find_one(FtdNatPolicy, condition=lambda
                    policy: policy.name == 'DND_DR_NAT')
                nat_policy_assignment = PolicyAssignment()
                nat_policy_assignment.targets = [device]
                nat_policy_assignment.policy = nat_policy
                api_service_fmc1.create(nat_policy_assignment)
                log.info('***** Successfully Assigned NAT policy to the FTD *****')

            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, nat_fqdn_ac_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_vdb_up" == FQDN_test_case or "Exception_with_Destination_FQDN_vdb_down" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                         vdb_access_policy_config.name)
            if ac_policy is None:
                ret_val = EVE_utils().create_access_policy(api_service_fmc1, device, vdb_access_policy_config)
                if not ret_val:
                    self.failed("AC Policy creation failed")

            if "Exception_with_Destination_FQDN_vdb_down" == FQDN_test_case:
                with steps.start("Creating dummy AC Rules"):
                    EVE_utils().create_multiple_rules(api_service_fmc1, vdb_access_policy_config, EVE_test_cases_data,
                                                      device)
                    log.info("Successfully created dummy AC Rules")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("VDB Upgrade/Downgrade"):
                log.info("Setting VDB builds and cfg parameters")
                vdb_utils.cfg.update({'api_service_fmc1': api_service_fmc1})
                vdb_utils.cfg.update({'ftd_label_dic': {'sensor1': 'sensor1', 'sensor2': 'sensor2'}})
                vdb_utils.cfg.update({'testbed': testbed})
                vdb_utils.cfg.update({'primaryDevice': testbed.devices.sensor2})
                vdb_utils.setVDBBuilds()
                ret_val = vdb_utils.vdbUpgradeRollbackScenario(steps, vdb_access_policy_config.name)
                if not ret_val:
                    self.failed("VDB Upgrade/Downgrade failed!")

            with steps.start("verify snort counter is increased for eve exempt"):
                time.sleep(sec)
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_unique" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, fqdn_unique_object_access_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_remove_objects" == FQDN_test_case:
            with steps.start("Delete FQDN Network Object"):
                ac_pol = api_service_fmc1.find_one(AccessPolicy, condition=lambda
                    policy: policy.name == fqdn_unique_object_access_policy_config.name)
                fqdnv4_object = api_service_fmc1.find_one(NetworkObject,
                                                          lambda fqdn: fqdn.name == 'dest_nw_fqdnv4_unique_obj_172')
                try:
                    ret_val = api_service_fmc1.delete(fqdnv4_object, container_id=ac_pol.id)
                except Exception as e:
                    pass
                    log.info("Deletion of FQDN Object is restricted, since it is assigned to Access Policy!!")

            with steps.start("Delete Exception Rule"):
                ac_pol = api_service_fmc1.find_one(AccessPolicy,
                                                   lambda obj: obj.name == fqdn_unique_object_access_policy_config.name)
                advanced_fragment = api_service_fmc1.find_one_by_record(AdvancedAccessPolicyFragment(),
                                                                        container_id=ac_pol.id)
                advanced_fragment.eve_settings.eveExceptionRuleList[0] = EveExceptionRuleListFragment()
                api_service_fmc1.update(advanced_fragment.eve_settings, container_id=ac_pol.id)
                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    log.info("ERROR: Exempt rule file is not present since exception rule list is removed")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "EVE_fqdn_process_name_change_v4" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))

            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_fqdn_process_name_change)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Update Exception Rule Process Name"):
                ac_pol = api_service_fmc1.find_one(AccessPolicy,
                                                   lambda obj: obj.name == EVE_fqdn_process_name_change.name)
                advanced_fragment = api_service_fmc1.find_one_by_record(AdvancedAccessPolicyFragment(),
                                                                        container_id=ac_pol.id)
                advanced_fragment.eve_settings.eveExceptionRuleList[0].processNameList = ["obj_test_cisco"]
                api_service_fmc1.update(advanced_fragment.eve_settings, container_id=ac_pol.id)
                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Update Network Object Name"):
                ac_pol = api_service_fmc1.find_one(AccessPolicy,
                                                   lambda obj: obj.name == EVE_fqdn_process_name_change.name)
                fqdnv4_object = api_service_fmc1.find_one(NetworkObject,
                                                          lambda fqdn: fqdn.name == Network_object_fqdnv4.name)
                fqdnv4_object.name = "test_" + Network_object_fqdnv4.name
                api_service_fmc1.update(fqdnv4_object, container_id=ac_pol.id)
                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("ERROR: Exempt counter not increased due to changing the process name and FQDN object name")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("ERROR: Validation of Unified Events in FMC failed due to changing the process name and FQDN object name")

        elif "Exception_with_Destination_FQDN_common" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, fqdn_common_object_access_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_FQDN_unresolved_ip" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, fqdn_unresolved_ip_access_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to ip is not resolved")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to unresolved ip")

        elif "Exception_with_Destination_FQDN_clear_cache" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           fqdn_clear_cache_access_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Disabling the DNS server"):
                endpoint2_ip = ConfigProvider(testbed, TestBedConstants.endpoint2.value)
                endpoint2_ssh = endpoint2_ip.get_ssh_connection()
                endpoint2_ssh.conn.execute("systemctl stop named")
                time.sleep(15)

            with steps.start("Clearing cache and checking the status in the FTD"):
                ftd1_ssh.conn.execute("clear dns")
                res = ftd1_ssh.conn.execute("show dns host client-1.eve.com")
                if "(cleared)" in res:
                    log.info("DNS Cleared Successfully!!")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to clear cache")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to clear cache")

            with steps.start("Enable the DNS server"):
                endpoint2_ssh.conn.execute("systemctl start named")
                time.sleep(15)

        elif "Exception_with_dns_ip_change_live_traffic" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,fqdn_live_traffic_access_policy_config)
                         if not ret_val:
                        self.failed("ERROR: AC Policy creation failed")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            count = 0
            file_path = "{}/eve_test_pcaps".format(base_dir)
            file_name = FQDN_test_name['pcap_file']

            with steps.start("get count"):
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
                count = EVE_utils().get_exempted_count_live_traffic(ftd1_ssh)
                if count == 0:
                    log.info("Counter not increased")
                elif not count:
                    log.error('Exempted issue')
                elif isinstance(count, int):
                    log.info("Counter : " + str(count))

            with steps.start("run script"):
                try:
                    def threaded_function(arg):
                        global spin_lock
                        log.info("Thread1 started......")
                        ed_ssh = arg['ed_ssh']
                        filename = arg['pcap']
                        log.info("Thread1 cmd executing")
                        spin_lock = True
                        ed_ssh.conn.execute("tcpreplay --intf1=eth1 --pps=100 {}".format(filename), timeout=600)
                        log.info("Thread1 cmd completed")

                    # start thread
                    global spin_lock
                    spin_lock = False
                    thread1 = Thread(target=threaded_function, args=[{'ed_ssh': endpoint1_ssh, 'pcap': "/root/eve_pcap/" + file_name}])
                    thread1.start()

                    # main thread will execute this
                    while (not spin_lock):
                        log.info(spin_lock)
                        pass
                    log.info("ED2 changes.....")
                    cmd = "sed -i 's/client-1        IN      A       172.16.2.2/client-1        IN      A       1.2.3.4/' /etc/bind/named.eve.com"
                    # 's/client-1[[:space:]]*IN[[:space:]]*A[[:space:]]*172.16.2.2/client-1        IN      A          1.2.3.4/'
                    endpoint2_ssh.conn.execute(cmd, timeout=5)
                    cmd = 'systemctl restart named'
                    endpoint2_ssh.conn.execute(cmd, timeout=5)
                    log.info("ED2 changes completed.....")

                    ftd1_ssh.conn.execute("clear dns")
                    ftd1_ssh.conn.execute("show dns host client-1.eve.com")

                    thread1.join()
                    log.info("Executed.....")
                except Exception as e:
                    pass

            with steps.start("verify counter"):
                new_count = EVE_utils().get_exempted_count_live_traffic(ftd1_ssh)
                log.info("new counter value : " + str(new_count))
                if isinstance(new_count, int):
                    if count == new_count:
                        log.info("Counter value matched")
                    else:
                        log.error("Counter value not matched")
                else:
                    log.error("Verify counter issue")

        elif "EVE_fqdn_clone_ac_network_object" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, fqdn_AC_policy_clone_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Clone access policy by enabling EVE"):
                ret_val= utility_eve.clone_access_policy(api_service_fmc1, device, fqdn_AC_policy_clone_config)
                if not ret_val:
                    self.failed("ERROR: Cloning AC Policy was failed")

            with steps.start("Verify that ExceptionRule present in the cloned policy"):
                cloning_acp = api_service_fmc1.find_one(AccessPolicy,
                                                       lambda obj: obj.name == fqdn_AC_policy_clone_config.name)
                advanced_fragment = api_service_fmc1.find_one_by_record(AdvancedAccessPolicyFragment(),
                                                                        container_id=cloning_acp.id)
                exceptionRuleList = advanced_fragment.eve_settings.eveExceptionRuleList
                if len(exceptionRuleList) == 0:
                    self.failed("ERROR: Exception rules were not present in the cloned AC Policy")

        elif "Exception_with_inheritance_behaviour" == FQDN_test_case:
            MODIFIED_URL = "testing.eve.com"
            with steps.start("create ac policy"):
                try:
                    access_policy = utility_eve.create_access_policy(api_service_fmc1, device,child_access_policy)
                    if not access_policy:
                        self.failed("ERROR: AC Policy creation failed")
                except Exception as e:
                    log.info(e)
                    self.failed("Error: AC policy creation failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

            with steps.start("Change network object"):
                network_obj = api_service_fmc1.find_one(NetworkObject,
                                                        lambda obj: obj.name == inheritance_network_obj.name)
                network_obj.value = MODIFIED_URL
                api_service_fmc1.update(network_obj)
                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to change in network object")


            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to change in network object")

        elif "Exception_with_import_export" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_import_export_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Export Access Policy"):
                ret_val = utility_eve.export_access_policy(api_service_fmc1, EVE_exempt_import_export_policy_config.name)
                if not ret_val:
                    self.failed("ERROR: Export of device specific Access policies is failed")

            with steps.start("Import Access Policy"):
                ret_val = utility_eve.import_access_policy_sfo(api_service_fmc1, "/tmp/ExportFile.sfo")
                if not ret_val:
                    self.failed("ERROR: Importing Access policy is failed")

        elif "EVE_dyn_attr_object_v4" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, dyn_attr_AC_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Enabling the Application-debug"):
                ret_val = CommonEve().traffic_validation(testbed)
                if not ret_val:
                    log.info("Traffic validation has failed")
                else:
                    log.info("Traffic validation is successfull")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "EVE_dyn_attr_object_v4_delete" == FQDN_test_case:
            with steps.start("Delete  Dynamic Atrribute Object"):
                ac_pol = api_service_fmc1.find_one(AccessPolicy, condition=lambda
                    policy: policy.name == dyn_attr_AC_policy_config.name)
                dyn_attr_object = api_service_fmc1.find_one(DynamicObject,
                                                          lambda dyn_attr: dyn_attr.name == 'DynamicObjectSampleeve')
                try:
                    ret_val = api_service_fmc1.delete(dyn_attr_object, container_id=ac_pol.id)
                except Exception as e:
                    pass
                    log.info("Deletion of Dynamic Attribute Object is restricted, since it is assigned to Access Policy!!")

        elif "EVE_dyn_attr_object_v4_remove_mapping" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, dyn_attr_AC_policy_remove_map_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start('Remove mappings from an existing object'):
                dyn_obj = api_service_fmc1.find_one(DynamicObject, lambda obj: obj.name == 'DynamicObjectSample_eve_remove_map')
                abp_map = api_service_fmc1.find_all(DynamicObjectMapping, container_id=dyn_obj.identifier)[0]
                abp_map.action = 'remove'
                api_service_fmc1.update(abp_map, container_id=dyn_obj.identifier)
                abp_maps = api_service_fmc1.find_all(DynamicObjectMapping, container_id=dyn_obj.identifier)
                assert len(abp_maps) == 1
                assert len(abp_maps[0].mappings) == 0

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to removal of mapping")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to removal of mapping")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_mutually_inclusive_dynamic" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           dyn_attr_AC_policy_common_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start('Add Dynamic Object to Access rule'):
                ac_pol = api_service_fmc1.find_one(AccessPolicy,
                                                   lambda obj: obj.name == dyn_attr_AC_policy_common_config.name)

                dynamic_object_fragment = api_service_fmc1.find_one(DynamicObject,
                                                                    lambda
                                                                        obj: obj.name == dynamic_object_data_common_config.name)
                log.info(dynamic_object_fragment)

                access_rule = api_service_fmc1.find_one(AccessRule,
                                                        lambda obj: obj.name == ac_rule_with_dynamic_object_common_config.name,
                                                        True,
                                                        container_id=ac_pol.id)

                access_rule.action = 'ALLOW'
                access_rule.destinationDynamicObjects = RuleDynamicObjectFragment(objects=[dynamic_object_fragment])

                api_service_fmc1.update(access_rule, container_id=ac_pol.id)
                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_mutually_exclusive_dynamic" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):

                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, dyn_attr_AC_policy_unique_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start('Creating Dynamic Object for Access Rule'):
                dynamic_object_data = DynamicObject(name=dynamic_object_data_unique.name,
                                                    description=dynamic_object_data_unique.description,
                                                    objectType=dynamic_object_data_unique.objectType,
                                                    _mappings=dynamic_object_data_unique._mappings)

                api_service_fmc1.create(dynamic_object_data)

            with steps.start('Add Dynamic Object to Access rule'):
                ac_pol = api_service_fmc1.find_one(AccessPolicy,
                                                   lambda obj: obj.name == dyn_attr_AC_policy_unique_config.name)

                dynamic_object_fragment = api_service_fmc1.find_one(DynamicObject,
                                                                    lambda
                                                                        obj: obj.name == dynamic_object_data_unique.name)
                log.info(dynamic_object_fragment)

                access_rule = api_service_fmc1.find_one(AccessRule,
                                                        lambda obj: obj.name == ac_rule_with_dynamic_object_unique.name,
                                                        True,
                                                        container_id=ac_pol.id)

                access_rule.action = 'ALLOW'
                access_rule.destinationDynamicObjects = RuleDynamicObjectFragment(objects=[dynamic_object_fragment])

                api_service_fmc1.update(access_rule, container_id=ac_pol.id)
                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "EVE_dynamic_process_name_change_v4" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           Dyn_attri_update_AC_policy_v4_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Update Exception Rule Process Name"):
                ac_pol = api_service_fmc1.find_one(AccessPolicy,
                                                   lambda obj: obj.name == Dyn_attri_update_AC_policy_v4_config.name)
                advanced_fragment = api_service_fmc1.find_one_by_record(AdvancedAccessPolicyFragment(),
                                                                        container_id=ac_pol.id)
                dynamic_object = api_service_fmc1.find_one(DynamicObject,
                                                           lambda fqdn: fqdn.name == dynamic_object_data_update.name)

                advanced_fragment.eve_settings.eveExceptionRuleList[0].processNameList = ["dynamic_obj_test_cisco"]
                advanced_fragment.eve_settings.eveExceptionRuleList[0].dynamicAttributes = dynamic_object
                api_service_fmc1.update(advanced_fragment.eve_settings, container_id=ac_pol.id)
                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Update Dynamic Object Name"):
                dynamic_object = api_service_fmc1.find_one(DynamicObject,
                                                           lambda fqdn: fqdn.name == dynamic_object_data_update.name)

                dynamic_object_mapping = DynamicObjectMapping(
                    action="add",
                    mappings=['172.16.6.6']
                )
                dynamic_object_mapping_list = api_service_fmc1.find_all(DynamicObjectMapping,
                                                                        container_id=dynamic_object.identifier)[0]

                dynamic_object_mapping_list.action = 'remove'
                api_service_fmc1.update(dynamic_object_mapping_list, container_id=dynamic_object.identifier)

                dynamic_object._mappings.append(dynamic_object_mapping)

                api_service_fmc1.update(dynamic_object._mappings, container_id=dynamic_object.id)

                try:
                    dynamic_object.name = "modified_" + dynamic_object.name
                    api_service_fmc1.update(dynamic_object, container_id=dynamic_object.id)
                except Exception as e:
                    log.info("Cannot Modify Name of Object")

                utility_eve.deploy_all(api_service_fmc1, device)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("ERROR: Exempt counter not increased due to modified mapping value")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("ERROR: Validation of Unified Events in FMC failed due to modified mapping value")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_rule_with_FQDN_DA_after_FTD-HA_failover" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                               ac_policy_dynamic_fqdn_switchover_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("switch over the ha"):
                utility_eve.switch_high_availability(api_service_fmc1)
            time.sleep(120)
            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd2_ssh, data_purge)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd2_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd2_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Dynamic_Object_Bulk_IP_Mapping" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))

            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           Dyn_attri_bulk_ip_AC_policy_v4_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

              with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased due to modified mapping value")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed due to modified mapping value")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Dynamic_Object_deployment_rollback" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create Ac policy with AC rule Alone"):
                ac_policy = api_service_fmc1.create(deployment_rollback_AC_policy_v4_config)
                log.info('***** Successfully created AC policy *****')
                ac_policy_assignment = PolicyAssignment()
                ac_policy_assignment.targets = [device]
                ac_policy_assignment.policy = ac_policy
                api_service_fmc1.create(ac_policy_assignment)
                log.info('***** Successfully assigned AC policy to the FTD *****')

            with steps.start("Do the deployment"):
                deployment_to_create = DeploymentRequest()
                deployment_to_create.deviceList.append(device)
                deployment = api_service_fmc1.create(deployment_to_create)
                rollbackID = "0050568B-AFA9-0ed3-0000-" + deployment.taskStatus.id.zfill(12)
                log.info(rollbackID)
            with steps.start("Updating AC_policy with Exception Rule"):
                ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                             deployment_rollback_AC_policy_v4_config.name)
                eve_setting = api_service_fmc1.find_one(EncryptedVisibilityEngineFragment, lambda obj: True,
                                                        container_id=ac_policy.id)

                eve_setting.eveExceptionRuleList = [new_ex_rule]
                api_service_fmc1.create(eve_setting, container_id=ac_policy.id)
                deployment2 = utility_eve.deploy_all(api_service_fmc1,device)


            with steps.start("Do the Rollback"):
                rollback = RollbackRequest()
                data = rollback.adapter.get_jobhistory(fmc1)
                logging.info(data)
                rollback.rollbackDeviceList = [
                    {"deploymentJobId": rollbackID, "deviceList": [data[0]["deviceList"][0]["deviceUUID"]]}]
                data = api_service_fmc1.create(rollback)
                logging.info(data)

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to deployment roll back")
                else:
                    log.error("ERROR: Exempt counter increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to deployment roll back")
                else:
                    log.error("ERROR: Validation of Unified Events in FMC failed")

        elif "Access_policy_with_bulk_exception_rules" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, ac_policy_bulk_exception_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Create Bulk Exception Rules"):
                ret_val = utility_eve.create_multiple_exception_rules(api_service_fmc1, ac_policy_bulk_exception_config,
                                                                      EVE_test_cases_data, device)
                if not ret_val:
                    self.failed("ERROR: Bulk Exception rules creation failed")

            # with steps.start("switch over the ha"):
            #     utility_eve.switch_high_availability(api_service_fmc1)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd2_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

            # with steps.start("switch over the ha"):
            #     utility_eve.switch_high_availability(api_service_fmc1)

        elif "Eve_Exception_Mercury_Stats" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))

            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,EVE_exception_mercury_stats_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/mitre_pcaps".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify mercury stats counter is not increased for eve exempt"):
                cmd_output = ftd1_ssh.conn.execute('show snort counters')
                if "Mercury Statistics" not in cmd_output:
                    log.info("Mercury Statistics counter is not present")
                else:
                    self.failed("Mercury Statistics is present")

        elif "Eve_Exception_Mercury_Module" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,EVE_exception_mercury_module_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Running the Mercury Module Debug Commands"):
                debug_output = utility_eve.mercury_module_debug(ftd1_ssh)
                if debug_output:
                    log.info("Running the Mercury Module Debug Commands passed")
                else:
                    log.error("Running the Mercury Module Debug Command failed")

            # with steps.start("Enabling the Application-debug"):
            #     ret_val = CommonEve().traffic_validation(testbed)
            #     if not ret_val:
            #         log.info("Traffic validation has failed")
            #     else:
            #         log.info("Traffic validation is successfull")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/mitre_pcaps".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            # with steps.start("Veryfying the Fingerprints"):
            #         time.sleep(15)
            #     wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
            #     if wget_ret_val:
            #         log.info("fingerprints are generated")

            with steps.start("Finding the module mercury"):
                mercury_module_output = ftd1_ssh.conn.execute("show packet debugs module mercury")
                if FQDN_test_name['mercury_keyword'] in mercury_module_output and FQDN_test_name['fingerprint_keyword'] in mercury_module_output and FQDN_test_name['process_keyword'] in mercury_module_output:
                    log.info("Mercury Module and Fingerprints details are present")
                else:
                    self.failed("Mercury Module and Fingerprints details are not present")

        elif "Eve_Exception_Exception_rule_order_1_with_ID" ==FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))

            with steps.start("Running the Eve-handler Module Debug Commands"):
                debug_output = utility_eve.eve_handler_module_debug(ftd1_ssh)
                if debug_output:
                    log.info("Running the Eve-handler Module Debug Commands passed")
                else:
                    log.error("Running the Eve-handler Module Debug Commands failed")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Finding the module Eve-Handler"):
                time.sleep(15)
                mercury_module_output = ftd1_ssh.conn.execute("show packet debugs module eve-handler")
                if FQDN_test_name['eve_handler_keyword'] in mercury_module_output and FQDN_test_name['rule_order_keyword'] in mercury_module_output:
                    log.info("Eve-Handler Module details are present")
                else:
                    self.failed("Eve-Handler Module details are not present")

        elif "Eve_Exception_dashboard" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
                    with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,EVE_exception_mercury_dashboard_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                pcap_file1 = FQDN_test_name['pcap_file']
                pcap_file2 = FQDN_test_name['pcap_file2']
                file_path1 = "{}/eve_test_pcaps/mitre_pcaps".format(base_dir)
                file_path2 = "{}/eve_test_pcaps/".format(base_dir)
                EVE_utils().dual_pcap_replay(api_service_fmc1,data_purge,endpoint1_ssh,ftd1_ssh,pcap_file1,pcap_file2,file_path1,file_path2)

            try:
                with steps.start("Getting into the instance folder"):
                    ftd1_ssh.conn.go_to('expert_state')
                    ftd1_ssh.conn.go_to('sudo_state')
                    ftd1_ssh.conn.execute('cd /ngfw/var/sf/detection_engines/*')

                with steps.start("Collecting the latest instance folder"):
                    instance_output = ftd1_ssh.conn.execute('ls -lrt')
                    lines = instance_output.splitlines()
                    for line in lines:
                        if 'instance-' in line:
                            latest_instance = line.split()[-1]
                    ftd1_ssh.conn.execute("cd "+latest_instance)
                    log.info(latest_instance)

                with steps.start("Collecting the latest unified log file inside latest instance folder"):
                    unified_logsFile_output = ftd1_ssh.conn.execute("ls -lrt")
                    files = unified_logsFile_output.splitlines()
                    latest_file = None

                    for file in files:
                        if "unified_events-2.log.17" in file:
                            file_name = file.split()[-1]
                            if latest_file is None or file_name > latest_file:
                                latest_file = file_name
                    log.info(latest_file)
                    log_command = "u2dump "+ latest_file +" | awk '/Type: 223\(0x000000df\)/,/Unified2 Record at offset/' > output.txt"
                    log.info(log_command)
                    time.sleep(120)
                    ftd1_ssh.conn.execute(log_command)
                    keyword_output = ftd1_ssh.conn.execute('cat output.txt')
                    Flag1 = FQDN_test_name['keyword1']
                    Flag2 = FQDN_test_name['keyword2']
                    if Flag1 or Flag2 in keyword_output:
                        log.info("Type: 223 keywords are present")
                    else:
                        self.failed("Type: 223 keywords are not present")
            except Exception as e:
                log.info(e)
                self.failed("Test case got Failed please read the exception")

        elif "Exception_rule_with_backup_restore" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = api_service_fmc1.create(EVE_exempt_Backup_Restore_fqdnv4v6_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Do the Backup"):
                backup_payload = BackupOptions(include_config=True, include_events=False, include_tid=False)
                backup_restore = BackupRestore(fmc1, polling_max_timeout=900)
                backup_name = "FMC_fmc_backup_restore-" + str(datetime.datetime.now().timestamp())
                archive_path = backup_restore.backup_fmc(backup_name, backup_options=backup_payload,
                                                         backup_timeout=1200)
                self.parent.parameters.update(fmc_config_path=archive_path)
                if archive_path is None:
                    self.failed("Error while Backing up FMC!")
                else:
                    log.info("Successfully Backed up FMC")

            with steps.start("delete ac policy"):
                ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                             EVE_exempt_Backup_Restore_fqdnv4v6_policy_config.name)
                api_service_fmc1.delete(ac_policy)

            with steps.start("Do the Restore"):
                archive_path = self.parent.parameters['fmc_config_path']
                try:
                    backup_restore = BackupRestore(fmc1, polling_max_timeout=900)
                    backup_restore.restore_fmc(archive_path, restore_options=BackupOptions(include_config=True,
                                                                                           include_events=False,
                                                                                           include_tid=False))
                    log.info("Successfully Restored FMC!!")
                except Exception as e:
                    log.info("Restore error : " + str(e))

            # wait for FMC to up
            time.sleep(bakup_time)
            with steps.start("Find and Deploy policy"):
                ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                             EVE_exempt_Backup_Restore_fqdnv4v6_policy_config.name)

                if ac_policy is None:
                    self.failed("Restore failed!!")

                ac_policy_assignment = PolicyAssignment()
                ac_policy_assignment.targets = [device]
                ac_policy_assignment.policy = ac_policy
                api_service_fmc1.create(ac_policy_assignment)

                deployment_to_create = DeploymentRequest()
                deployment_to_create.deviceList.append(device)
                api_service_fmc1.create(deployment_to_create)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, FQDN_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

@aetest.processors(pre=[break_high_availability])
class CommonCleanup(ftltest.CommonCleanup):
    @aetest.subsection
    def unassign_interfaces_on_ftd(self, api_service_fmc1: APIService, device):
        for phy in api_service_fmc1.find_all(PhysicalInterface, container_id=device.identifier):
            if phy.name == 'Diagnostic0/0' or phy.name == 'Management0/0':
                pass
            else:
                try:
                    phy.ipv4 = None
                    phy.ipv6 = None
                    phy.ifname = ''
                    phy.enabled = False
                    phy.securityZone = ''
                    api_service_fmc1.update(phy, container_id=device.identifier)
                except Exception as err:
                    log.error(err)
        EVE_utils().deploy_all(api_service_fmc1, device)

if __name__ == '__main__':
    aetest.main()

