import copy
import re
import time
import os
import polling
from ats import aetest
import logging
import requests
# from pyats.aetest.steps import Steps
from lib.models.deploy.model import DeploymentRequest
from lib.models.deploy.pendingchanges.model import PendingChanges
from lib.models.devices.device_management.device.inline_sets.inline_set.model import InlineSet
from lib.models.devices.device_management.high_availability.constants import UpdateHAActions
from lib.models.devices.device_management.high_availability.model import HighAvailability
from lib.models.devices.device_management.device.interfaces.physical_interface.model import PhysicalInterface
from lib.models.devices.ftdnat.model import FtdNatPolicy
from lib.models.fragments.inline_pairs.model import InlinePairsFragment
from lib.models.upgrade.access_policy.model import AccessPolicy
from tests.feature.ftd.tests.DAQ.Defect_Automation.Test_Cases.DAQ_5.DAQ5_utils import DAQ5_utility
from tests.feature.ftd.tests.EVE.Mitre_Test import CommonEve
from unicon.eal.dialogs import Dialog
import fmc as fmc_mod_own
import yaml
from lib.common_modules.cli_connection import get_cli_connection
from lib.models.devices.device_management.device.static_route.ipv4.model import IPV4StaticRoute
from lib.constants import TestBedConstants
from lib.models.devices.device_management.device.model import Device
from lib.services.api_service import APIService
import lib.commons.commons as ftltest
from lib.services.data.store import store
from lib.services.config_provider import ConfigProvider
from lib.models.policies.access_control.ssl.ssl_policy.model import SSLPolicy
from lib.models.fragments.ssl_advanced_options.model import SSLAdvancedOptionsFragment
from tests.feature.ngfw.Snort.tests.unified_automation_snort_teacats_724.lsp_upgrade_downgrade import LspLib
from tests.shared_libraries.common_functions import CommonFunction
from tests.feature.fmc.devices.device_management.device.high_availability.ftdha_Utility import Utility
from tests.feature.fmc.policies.intrusion.snort3_intrusion.snort3_intrusion_utility import Snort3Utility
from tests.feature.ftd.tests.EVE.EVE_utils import EVE_utils
from pathlib import Path
import tests.feature.ngfw.Snort.tests.unified_automation_snort_teacats_724.unified_automation_utility as vdb_utils
from lib.models.policies.access_control.access_control.access_policy.policy_assignment.model import PolicyAssignment
from lib.features_constants import Features76
from lib.utils.functions import set_testcase_feature, set_tims_testcase
from tests.feature.fmc.devices.device_management.device.high_availability.code_coverage_Utility import \
    CodeCoverageUtility
from tests.feature.fmc.devices.device_management.device.high_availability. \
    interface_mac_addresses.interface_mac_addresses_test_rcv.ftdha_mac_addresses_utility import MacAddressUtility

DATA_PATH = 'data/EVE_Exclusion_list_HA_TBAAS_data.yaml'
base_dir = os.path.dirname(__file__)
test_file_path = ["{}/{}".format(base_dir, DATA_PATH), __file__]
EVE_test_cases_data = yaml.safe_load(Path(test_file_path[0]).read_text())
EVE_test = EVE_test_cases_data['EVE_test_cases']
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


path = ("{}/{}".format(base_dir, DATA_PATH))

import argparse
parser = argparse.ArgumentParser(description="EVE Precommit")
parser.add_argument('--precommit', default=False)
args = parser.parse_known_args()[0]
precommit = args.precommit
if precommit == 'True':
    EVE_test = EVE_test_cases_data['EVE_precommit_test_cases']
    log.info("Running only precommit testcases")
else:
    EVE_test = EVE_test_cases_data['EVE_test_cases']
    log.info("Running all the testcases")

#
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
    def set_up(self, testbed, api_service_fmc1: APIService, current_version):
        global ftd_type
        global ftd1_ssh
        global ftd2_ssh
        global ftdha_ipv4
        global fmc_API
        global required_interface
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
        endpoint1_wget_ip = testbed.devices["endpoint1"].interfaces["eth3"].ipv4.ip.compressed
        endpoint2_wget_ip = testbed.devices["endpoint2"].interfaces["eth3"].ipv4.ip.compressed
        client_ip_address = str(testbed.devices[TestBedConstants.endpoint2.value].interfaces.eth1.ipv4.ip)
        server_ip_address = str(testbed.devices[TestBedConstants.endpoint1.value].interfaces.eth1.ipv4.ip)
        available_interface = testbed.devices[TestBedConstants.endpoint2.value].interfaces.eth1.mode
        if available_interface == "inline":
            required_interface = 'eth1'


        fmc = self.parent.parameters[self.args.fmc_alias]
        interface_alias = {"management1"}
        if interface_alias.issubset(testbed.devices[TestBedConstants.fmc1.value].interfaces.aliases):
            fmc_ip = str(fmc.device.interfaces["management1"].ipv4.ip)
        else:
            fmc_ip = str(fmc.device.connections.management.ip)
        utility_object1 = MacAddressUtility()
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
        # print(f'\n\n\nFTD2 Version is {ftd2_major_version}\n\n\n\n')
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
        code_coverage_utility = CodeCoverageUtility()
        # endpoint1.conn.execute("route add -net 0.0.0.0/0 gw {}".format(inside_interface_ip))
        # endpoint2.conn.execute("route add -net 0.0.0.0/0 gw {}".format(outside_interface_ip))
        self.parent.parameters.update({
            "code_coverage_utility": code_coverage_utility,
            'inlineset_config': store.get("file:{}".format(self.args.data_file[0]),
                                          root_object='inline_set.test_rest_inlineset'),
            "EVE_block_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                 root_object="access_policies.EVE_block_policy"),
            "EVE_exempt_host_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                       root_object="access_policies.EVE_exempt_host_policy"),
            "EVE_exempt_host_v6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                          root_object="access_policies.EVE_exempt_host_v6_policy"),
            "EVE_exempt_network_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                          root_object="access_policies.EVE_exempt_network_policy"),
            "EVE_exempt_network_v6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                             root_object="access_policies.EVE_exempt_network_v6_policy"),
            "EVE_exempt_range_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                        root_object="access_policies.EVE_exempt_range_ip_policy"),
            "EVE_exempt_range_ipv6_policy_config":store.get("file:{}".format(self.args.data_file[0]),
                                                             root_object="access_policies.EVE_exempt_range_ipv6_policy"),
            "EVE_exempt_process_name_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                               root_object="access_policies.EVE_exempt_process_name_policy"),
            "EVE_exempt_with_tsid_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                            root_object="access_policies.EVE_exempt_with_TSID_policy"),
            "EVE_exempt_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                  root_object="access_policies.EVE_exempt_policy"),
            "EVE_exempt_host_policy_ssl_config": store.get("file:{}".format(self.args.data_file[0]),
                                                           root_object="access_policies.EVE_exempt_host_policy_ssl"),
            "EVE_exempt_lsp_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                           root_object="access_policies.EVE_exempt_host_lsp_policy"),
            "access_policy_IFR_CSCwj05620": store.get("file:{}".format(self.args.data_file[0]),
                                                      root_object="access_policies.access_policy_IFR_CSCwj05620"),
            "access_policy_IFR_CSCwj12669": store.get("file:{}".format(self.args.data_file[0]),
                                                      root_object="access_policies.access_policy_IFR_CSCwj12669"),
            "data_purge": store.get("file:{}".format(self.args.data_file[0]), root_object='purge.data_purge'),
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
            'ftd1_major_version': ftd1_major_version,
            'ftd2_major_version': ftd2_major_version,
            "fmc_ssh": fmc_ssh,
            'utility1': utility_object1,
            'fmc_ip': fmc_ip,
            'current_version': current_version,
            'primary_fmc': primary_fmc,
            'ftdha_ipv4': ftdha_ipv4,
            'ha_name': "HA-Global-Domain",
            'endpoint1_name': "endpoint1",
            'endpoint2_name': "endpoint2",
            'endpoint1_ssh': endpoint1,
            'endpoint2_ssh': endpoint2,
            'client_ip_address':client_ip_address,
            'server_ip_address': server_ip_address,
            "first_inline_interface": found_first_inline_interface,
            "second_inline_interface": found_second_inline_interface,
            "required_interface" : required_interface

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
                         device: Device, first_inline_interface: PhysicalInterface,
                         second_inline_interface: PhysicalInterface):
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
                                 utility1, utility_eve, code_coverage_utility, primary_fmc, fmc_ssh):
        utility1.perform_deploy_on_dirty_devices(api_service_fmc1, primary_fmc)

        log.info('\n Check if build is code coverage, if YES then pause for 300 seconds \n')
        code_coverage_utility.check_for_code_coverage_builds(fmc_ssh)

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

@aetest.loop(EVE_test_case=list(EVE_test.keys()))
class EVE_Testcases(aetest.Testcase):
    @aetest.setup
    def set_feature(self):
        set_testcase_feature([Features76.feature44.value])
        set_tims_testcase("Txw16179267c, Txw16179269c, Txw16179277c, Txw16179282c, Txw16179271c, Txw16179276c,"
                          "Txw16179320c, Txw16189247c, Txw16179331c, Txw16179334c,Txw16187161c, Txw16179339c")
    @aetest.test
    def eve_test_cases(self, steps, EVE_test_case, utility, api_service_fmc1, utility_eve, ftd1_ssh, fmc1,ftd2_ssh,ftd2_cli,
                       testbed, device, EVE_exempt_host_policy_config, ftd1_cli, endpoint1_ssh, endpoint2_ssh,
                       data_purge, EVE_exempt_network_policy_config, EVE_exempt_range_policy_config, ftdha_ipv4,
                       EVE_exempt_process_name_policy_config, EVE_exempt_with_tsid_policy_config, current_version,
                       EVE_exempt_policy_config, EVE_exempt_host_v6_policy_config, EVE_exempt_network_v6_policy_config,
                       EVE_exempt_range_ipv6_policy_config, EVE_block_policy_config, EVE_exempt_host_policy_ssl_config,EVE_exempt_lsp_policy_config,
                       access_policy_IFR_CSCwj05620, access_policy_IFR_CSCwj12669, client_ip_address, server_ip_address,required_interface):
        EVE_test_name = EVE_test[EVE_test_case]
        log.info("********** {}".format(EVE_test_name))
        delay = 60
        temp = list()
        temp.append(device)
        process_name_list = list()
        current_version = float(current_version[:3])
        log.info(current_version)
        if "Getting_field_value" == EVE_test_case:
            global process_name, threat_score
            with steps.start("Create access policy by enabling EVE"):
                # EVE_exempt_host_policy_config.advanced.eve_settings.blockThreshold = 50
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_block_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = "2019-12-10-Hancitor-infection-with-Ursnif-and-Cobalt-Strike_REWRITE.pcap"
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            time.sleep(delay)
            with steps.start("Validation of unified events in FMC"):
                process_name, threat_score = utility_eve.get_block_events(fmc1)

        elif "Exception_with_Destination_IP" == EVE_test_case:
            threat_score = threat_score[:2]
            log.info("Testcase: {}".format(EVE_test_case))
            log.info("n/w object: {}".format(EVE_test_name['dst_object']))
            log.info("pcap file : {}".format(EVE_test_name['pcap_file']))
            with steps.start("Create access policy by enabling EVE"):
                EVE_exempt_host_policy_config.advanced.eve_settings.blockThreshold = threat_score
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_host_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(60)

                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_IPv6" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            log.info("n/w object: {}".format(EVE_test_name['dst_object']))
            log.info("pcap file : {}".format(EVE_test_name['pcap_file']))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_host_v6_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_IP_network" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_network_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")

                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                                 self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_IPv6_network" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_network_v6_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_IP_range" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device, EVE_exempt_range_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_IPv6_range" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_range_ipv6_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_Destination_Process_name" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("Create access policy by enabling EVE"):
                if len(process_name_list) == 0:
                    process_name_list.append(process_name)
                EVE_exempt_process_name_policy_config.advanced.eve_settings.eveExceptionRuleList[
                    0].processNameList = process_name_list
                EVE_exempt_process_name_policy_config.advanced.eve_settings.blockThreshold = threat_score
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_process_name_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, process_name)
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_TSID_enabled" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_with_tsid_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")
            with steps.start("Enabling the Application-debug"):
                ret_val = CommonEve().traffic_validation(testbed)
                if not ret_val:
                    log.info("Traffic validation has failed")
                else:
                    log.info("Traffic validation is successfull")
            with steps.start("Running the traffic using Aquila-Replay in client and server"):
                pcap_path = "eve_test_pcaps"
                pcap = EVE_test_name['pcap_file']
                EVE_utils().Aquila_replay(ftd1_ssh,endpoint1_ssh,endpoint2_ssh,api_service_fmc1, data_purge,base_dir, pcap_path,pcap,client_ip_address,server_ip_address,required_interface)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    log.info("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(120)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_snort_toggle" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            process_name_list.append(process_name)
            EVE_exempt_policy_config.advanced.eve_settings.eveExceptionRuleList[0].processNameList = process_name_list
            EVE_exempt_policy_config.advanced.eve_settings.blockThreshold = threat_score
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, process_name)
                if not ret_val:
                    self.failed("ERROR: Exempt rule file is not present")
            if current_version < 7.7:
                with steps.start("Verify Snort Version and Toggle"):
                    if not CommonFunction().toggle_snort(ftd1_ssh, device, api_service_fmc1):
                        self.failed('Error During Snort Toggle, Aborting')
                    else:
                        log.info("Deploy Toggle Changes")
                        utility_eve.deploy_all(api_service_fmc1, device)
                    with steps.start("Verify that exempt.rules file is not present"):
                        log.info("exempt rule testcase")
                        ret_val = utility_eve.check_for_rule_file(ftd1_cli, process_name)
                        if ret_val:
                            self.failed("ERROR: Exempt rule file is present")
                with steps.start("Verify Snort Version and Toggle"):
                    if not CommonFunction().toggle_snort(ftd1_ssh, device, api_service_fmc1):
                        self.failed('Error During Snort Toggle, Aborting')
                    else:
                        log.info("Deploy Toggle Changes")
                        utility_eve.deploy_all(api_service_fmc1, device)
                    with steps.start("Verify that exempt.rules file is present"):
                        log.info("exempt rule testcase")
                        ret_val = utility_eve.check_for_rule_file(ftd1_cli, process_name)
                                    with steps.start("Enabling the Application-debug"):
                ret_val = CommonEve().traffic_validation(testbed)
                if not ret_val:
                    log.info("Traffic validation has failed")
                else:
                    log.info("Traffic validation is successfull")
            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
                # CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh,
                #                         data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    log.info("fingerprints are not generated")
            with steps.start("verify snort counter is increased for Mitre pcap"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                log.info(ret_val)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
                else:
                    log.info("Exempt counter increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(60)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("Error: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "SSl_QUIC_disable" == EVE_test_case:
            ssl_policy = api_service_fmc1.find_one(SSLPolicy,
                                                   condition=lambda policy: policy.name == "Exclusion_ssl_policy")

            if ssl_policy is None:
                self.failed("There is no Active SSL policy")
            else:
                ssl_policy.advanced_options = SSLAdvancedOptionsFragment(**{"quic_decryption": False,
                                                                            "tls13_decryption": False,
                                                                            "adaptive_probe": False})
                api_service_fmc1.update(ssl_policy)
                EVE_utils().deploy_all(api_service_fmc1, device)

            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, EVE_test_name['dst_object'])
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
                file_name = EVE_test_name['pcap_file']
                # utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
                CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh,
                                        data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    log.info("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")

            with steps.start("Validation of unified events in FMC"):
                time.sleep(60)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("Error: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "Exception_with_HA_switch_over" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("switch over the ha"):
                ret_val = utility_eve.switch_high_availability(api_service_fmc1)
                if not ret_val:
                    self.failed("ERROR: Failed to switch the active peer")
                # utility_eve.switch_high_availability_pa_StandbyActive(api_service_fmc1, ftd1_ssh, ftd2_ssh,
                #                                                       ftdha_ipv4, utility)
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                # ret_val = utility_eve.check_for_rule_file(ftd2_cli, process_name)
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    log.info("fingerprints are not generated")

            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd2_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")
            with steps.start("switch over the ha"):
                utility_eve.switch_high_availability(api_service_fmc1)

        elif "Exception_with_HA_break_reform" == EVE_test_case:
            log.info("Testcase: {}".format(EVE_test_case))
            with steps.start("Break the HA"):
                break_high_availability()
            with steps.start("Reform the HA"):
                time.sleep(300)
                ret_val = utility_eve.create_high_availability(api_service_fmc1, testbed, ftd1_ssh, ftd2_ssh,
                                                               ftdha_ipv4, utility)
                if not ret_val:
                    self.failed("ERROR: HA reform failed")
            with steps.start("Verify that exempt.rules file is present"):
                log.info("exempt rule testcase")
                ret_val = utility_eve.check_for_rule_file(ftd1_cli, process_name)
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
                file_name = EVE_test_name['pcap_file']
                utility_eve.pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    self.failed("fingerprints are not generated")
            with steps.start("verify snort counter is increased for eve exempt"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    self.failed("ERROR: Exempt counter not increased")
            with steps.start("Validation of unified events in FMC"):
                time.sleep(delay)
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    self.failed("ERROR: Validation of Unified Events in FMC failed")
                else:
                    log.info("Validation of Unified Events in FMC passed")

        elif "IFR_CSCwj05620" == EVE_test_case:
            with steps.start("Create Access Policy with whitespace in process name"):
                ret_val = EVE_utils().create_access_policy(api_service_fmc1, device, access_policy_IFR_CSCwj05620)
                if not ret_val:
                    self.failed("AC Policy whitespace in process name creation failed")

        elif "IFR_CSCwj12669" == EVE_test_case:
            with steps.start("Create Access Policy with duplicate exception rule"):
                ac_policy = api_service_fmc1.create(access_policy_IFR_CSCwj12669)
                ac_policy_assignment = PolicyAssignment()
                ac_policy_assignment.targets = [device]
                ac_policy_assignment.policy = ac_policy
                api_service_fmc1.create(ac_policy_assignment)
                try:
                    deployment_to_create = DeploymentRequest()
                    deployment_to_create.deviceList.append(device)
                    api_service_fmc1.create(deployment_to_create)
                except Exception as e:
                    print(e)
                    self.passed("AC Policy Creation Failed because of Duplicate Exception Rule")
                else:
                    self.failed("Deployment Successful even though AC Policy has Duplicate Exception Rule")


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
