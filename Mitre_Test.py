import os
import re
import yaml
import logging
import time
import polling
import tests.feature.ngfw.Snort.tests.unified_automation_snort_teacats_724.unified_automation_utility as vdb_utils
from pathlib import Path
import lib.commons.commons as ftltest
from ats import aetest
from lib.features_constants import Features76
from lib.models.devices.device_management.high_availability.model import HighAvailability
from lib.models.fragments.advanced_access_policy.model import AdvancedAccessPolicyFragment
from lib.services.api_service import APIService
from lib.services.data.store import store
from lib.constants import TestBedConstants
from lib.services.config_provider import ConfigProvider
from lib.models.devices.device_management.device.inline_sets.inline_set.model import InlineSet
from lib.utils.functions import set_tims_testcase, set_testcase_feature
from tests.feature.fmc.devices.device_management.device.high_availability.interface_mac_addresses.interface_mac_addresses_test_rcv.ftdha_mac_addresses_utility import \
    MacAddressUtility
from tests.feature.fmc.devices.device_management.device.high_availability.code_coverage_Utility import \
    CodeCoverageUtility
from tests.system.fmc_cli.fmc_sru import SruUpdate
from tests.system.utils.apex.util_topology_apex import get_traffic_interface_pairs
from lib.models.fragments.inline_pairs.model import InlinePairsFragment
from lib.models.devices.device_management.device.interfaces.physical_interface.model import PhysicalInterface
from lib.models.policies.access_control.intrusion.intrusion_policy.model import IntrusionPolicy
from lib.models.policies.access_control.malware_and_file.file_policy.model import FilePolicy
from lib.models.policies.access_control.access_control.access_policy.model import AccessPolicy
from tests.feature.fmc.devices.device_management.device.high_availability.ftdha_Utility import Utility
from lib.common_modules.cli_connection import get_cli_connection
from lib.models.deploy.model import DeploymentRequest
from lib.models.devices.device_management.device.model import Device
from lib.services.eventing.constants import ConnectionEventsFilters
from lib.services.eventing.events import Events
from unicon.eal.dialogs import Dialog
from lib.services.eventing.constants import EventsTypes
from tests.shared_libraries.common_functions import CommonFunction
from lib.models.policies.access_control.access_control.access_policy.policy_assignment.model import PolicyAssignment
from tests.feature.ftd.tests.EVE.EVE_utils import EVE_utils
from lib.services.system.tools.backup_restore import BackupRestore, BackupOptions

DATA_PATH = 'data/mitre-data.yaml'
PCAP_REPLAY_CASES_FILE_NAME = 'data/pcap_replay.yaml'
base_dir = os.path.dirname(__file__)
test_file_path1 = ["{}/{}".format(base_dir, DATA_PATH), __file__]
tc_path = ["{}/{}".format(base_dir, PCAP_REPLAY_CASES_FILE_NAME), __file__]
mitre_test_cases_data = yaml.safe_load(Path(tc_path[0]).read_text())
mitre_test_cases = mitre_test_cases_data['Mitre_testcases']
mitre_tags = mitre_test_cases_data['mitre_tags']
EVE_test_cases_data = yaml.safe_load(Path(test_file_path1[0]).read_text())
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

import argparse

parser = argparse.ArgumentParser(description="EVE Precommit")
parser.add_argument('--precommit', default=False)
args = parser.parse_known_args()[0]
precommit = args.precommit
if precommit == 'True':
    mitre_test_cases = mitre_test_cases_data['Mitre_precommit_testcases']
    log.info("Running Only precomit testcases")
else:
    mitre_test_cases = mitre_test_cases_data['Mitre_testcases']
    log.info("Running All the testcases")



class CommonSetup(ftltest.CommonSetup):
    @aetest.subsection
    def set_up(self, testbed, api_service_fmc1: APIService, fmc1: ConfigProvider,current_version):
        base_dir = os.path.dirname(__file__)
        ftd1_ip = str(testbed.devices[TestBedConstants.sensor1.value].interfaces["management1"].ipv4.ip)
        ftd2_ip = str(testbed.devices[TestBedConstants.sensor2.value].interfaces["management1"].ipv4.ip)
        self.args.data_file.extend(["{}/{}".format(base_dir, DATA_PATH), __file__])
        log.info('\n Getting the Device Handle for ssh connection to the Devices \n')
        ##sensor 1 and 2  ##
        ftd1_sec = ConfigProvider(testbed, TestBedConstants.sensor1.value)
        ftd2_sec = ConfigProvider(testbed, TestBedConstants.sensor2.value)
        ## endpnt 1 and 2 ##
        endpoint1_ip = ConfigProvider(testbed, TestBedConstants.endpoint1.value)
        endpoint2_ip = ConfigProvider(testbed, TestBedConstants.endpoint2.value)
        ## client ip -> end pnt 2 ##
        ## server ip -> end pnt 1 ##
        client_ip_address = str(testbed.devices[TestBedConstants.endpoint2.value].interfaces.eth1.ipv4.ip)
        server_ip_address = str(testbed.devices[TestBedConstants.endpoint1.value].interfaces.eth1.ipv4.ip)
        ## ssh conn end pnt 1 and 2 ##
        endpoint1 = endpoint1_ip.get_ssh_connection()
        endpoint2 = endpoint2_ip.get_ssh_connection()
        userName = str(testbed.devices.fmc1.connections.management.user)
        global ftd1_ssh
        global ftd2_ssh
        device_ip = testbed.devices[TestBedConstants.sensor1.value].interfaces["management1"].ipv4.ip.compressed
        print(device_ip)
        device = api_service_fmc1.find_one(Device, condition=lambda device_obj: device_obj.hostName == device_ip)
        utility_object1 = MacAddressUtility()
        code_coverage_utility = CodeCoverageUtility()
        ftd1_ssh = ftd1_sec.get_ssh_connection()
        utility_object = Utility()
        fmc_1 = ConfigProvider(testbed, TestBedConstants.fmc1.value)
        fmc_ssh = fmc_1.get_ssh_connection()
        ftd1_cli = get_cli_connection(testbed, device_label="sensor1")
        ftd2 = api_service_fmc1.find_one(Device, lambda obj: obj.hostName == ftd2_ip)
        ftd1 = api_service_fmc1.find_one(Device, lambda obj: obj.hostName == ftd1_ip)
        ftd2_cli = get_cli_connection(testbed, device_label="sensor2")
        ftd2_ssh = ftd2_sec.get_ssh_connection()
        ftdha_ipv4 = store.get("file:{}".format(self.args.data_file[0]),
                               root_object='ftd_ha.ftdha_global_domain')
        utility_eve = EVE_utils()
        tbyaml_data = {dev: get_traffic_interface_pairs(testbed, dev) for dev in testbed.devices.keys() if
                       'router' not in testbed.devices[dev].type}
        ftd_routed_data = \
            [dev for dev in tbyaml_data[TestBedConstants.sensor1.value] for k, v in dev.items() if dev[k] == 'routed'][
                0]
        endpoint1_routed_data = \
            [dev for dev in tbyaml_data[TestBedConstants.endpoint1.value] for k, v in dev.items() if
             dev[k] == 'routed'][0]
        endpoint2_routed_data = \
            [dev for dev in tbyaml_data[TestBedConstants.endpoint2.value] for k, v in dev.items() if
             dev[k] == 'routed'][0]
        inside_host_network = str(endpoint1_routed_data['source_destination_route_ipv4'])
        inside_host_gateway = str(ftd_routed_data['source_gateway_ipv4'])
        outside_host_network = str(endpoint2_routed_data['destination_source_route_ipv4'])
        outside_host_gateway = str(ftd_routed_data['destination_gateway_ipv4'])
        # route addition at the endpoints
        endpoint1.conn.execute("route add -net " + inside_host_network + " gw " + inside_host_gateway)
        endpoint2.conn.execute("route add -net " + outside_host_network + " gw " + outside_host_gateway)
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
        self.parent.parameters.update({
            "fmc_ssh": fmc_ssh,
            "device": device,
            "ftd1": ftd1,
            "ftd2": ftd2,
            'fmc1': fmc1,
            'fmc_1': fmc_1,
            "ftd1_cli": ftd1_cli,
            "ftd2_cli": ftd2_cli,
            "yaml_data": self.args.data_file[0],
            "ftd1_ip": ftd1_ip,
            'ftd1_ssh': ftd1_ssh,
            'ftd2_ssh': ftd2_ssh,
            'utility_eve': utility_eve,
            'testbed': testbed,
            'utility': utility_object,
            'utility1': utility_object1,
            "code_utility": code_coverage_utility,
            'mitre_tags': mitre_tags,
            'current_version': current_version,
            "token_config": store.get("file:{}".format(self.args.data_file[0]),
                                      root_object='smart_license.token_value'),
            'inlineset_config': store.get("file:{}".format(self.args.data_file[0]),
                                          root_object='inline_set.test_rest_inlineset'),
            "ssl_Ac_Policy": store.get("file:{}".format(self.args.data_file[0]),
                                       root_object='access_policies.SSL_Ac_Policy'),
            "encrypted_dns_Ac_Policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                       root_object='access_policies.Encrypted_dns_AC_Policy'),
            "eve_enabled_AC_Policy": store.get("file:{}".format(self.args.data_file[0]),
                                               root_object='access_policies.EVE_Enabled_AC_Policy'),
            "ac_test_intrusion_Policy": store.get("file:{}".format(self.args.data_file[0]),
                                                  root_object='access_policies.EVE_Enabled_AC_Policy_Intrusion_Policy'),
            "ac_test_file_Policy": store.get("file:{}".format(self.args.data_file[0]),
                                                  root_object='access_policies.EVE_Enabled_AC_Policy_File_Policy'),
            "intrusion_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                 root_object='intrusion_policy.simple_policy'),
            "file_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                            root_object='file_policy.simple_file_policy'),
            "appid_trust_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                   root_object='access_policies.EVE_Enabled_TRUST_APPID'),
            "app_block_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                 root_object='access_policies.EVE_Enabled_APP_BLOCK'),
            "ac_policy_mitre_config": store.get("file:{}".format(self.args.data_file[0]),
                                                root_object='access_policies.Mitre_Tag_AC_Policy'),
            "ac_policy_flow_allow_block": store.get("file:{}".format(self.args.data_file[0]),
                                                    root_object='access_policies.EVE_Enabled_Flow_Allow_Block'),
            "vdb_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                  root_object='access_policies.VDB_Access_Policy'),
            "eve_si_ac_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                 root_object='access_policies.SI_Enabled_AC_Policy'),
            "eve_SRU_Ac_config": store.get("file:{}".format(self.args.data_file[0]),
                                           root_object='access_policies.SRU_Ac_Policy'),
            "ac_backup_restore_config": store.get("file:{}".format(self.args.data_file[0]),
                                                  root_object='access_policies.Backup_restore_AC_policy'),
            "data_purge": store.get("file:{}".format(self.args.data_file[0]), root_object='purge.data_purge'),
            'devices': api_service_fmc1.find_all(Device),
            'ftd1_sec': ftd1_sec,
            'ftdha_ipv4': ftdha_ipv4,
            'ha_name': "HA-Global-Domain",
            'endpoint1_name': "endpoint1",
            'endpoint2_name': "endpoint2",
            'endpoint1_ssh': endpoint1,
            'endpoint2_ssh': endpoint2,
            'user_name': userName,
            'client_ip_address': client_ip_address,
            'server_ip_address': server_ip_address,
            "first_inline_interface": found_first_inline_interface,
            "second_inline_interface": found_second_inline_interface,
        })
 ##################################################################################################################
    # FUNCTION NAME: creating_physical_inline_interface(self, api_service_fmc1, first_inline_interface,              #
    #                                              second_inline_interface,device: Device):                          #
    # DESCRIPTION  : Creating Physical inline interface                                                              #
    # ARGUMENTS    : api_service_fmc1 - Object of the APIservice                                                     #
    #                first_inline_interface - Object of Interface 1                                                  #
    #                second_inline_interface - Object of Interface 2                                                 #
    #                device:Device - Keyword of device(FTD) for validating the events in FMC                         #
    # RETURN VALUE : #NA                                                                                             #
    ##################################################################################################################
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
    #################################################################################################################
    # FUNCTION NAME: create_inlineset(self, api_service_fmc1: APIService, inlineset_config: InlineSet,               #
    #                          device: Device, first_inline_interface: PhysicalInterface,                            #
    #                          second_inline_interface: PhysicalInterface):                                          #
    # DESCRIPTION  : Creating Inlineset                                                                              #
    # ARGUMENTS    : api_service_fmc1:APIService - Object of the APIservice                                          #
    #                first_inline_interface:PhysicalInterface - Object of PhysicalInterface                          #
    #                second_inline_interface:PhysicalInterface - Object of Interface PhysicalInterface               #
    #                device:Device - Keyword of device(FTD) for validating the events in FMC                         #
    # RETURN VALUE : #NA                                                                                             #
    ##################################################################################################################
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
    ##################################################################################################################
    # FUNCTION NAME: create_high_availability_ipv4(self, api_service_fmc1: APIService, fmc1, testbed, ftd1, ftd2,    #
    #                                       ftdha_ipv4: HighAvailability, code_utility, fmc_ssh):                    #
    # DESCRIPTION  : Creates High Availability Device                                                                #
    # ARGUMENTS    : #api_service_fmc1: APIService - API Service Object for FMC1                                     #
    #                fmc1 - Object of FMC                                                                            #
    #                testbed - Object of testbed                                                                     #
    #                ftd1_ssh - Object of FTD1                                                                       #
    #                ftd2_ssh - Object of FTD2                                                                       #
    #                utility1 - Object of MACAddressUtility                                                          #
    #                #ftdha_ipv4 - Object of the FTD HA IPV4                                                         #
    #                fmc_ssh - ssh Object of FMC                                                                     #
    # RETURN VALUE : #NA                                                                                             #
    ##################################################################################################################
    @aetest.subsection
    def create_high_availability(self, api_service_fmc1: APIService, testbed, ftd1_ssh, ftd2_ssh, ftdha_ipv4, utility1):
        EVE_utils().create_high_availability(api_service_fmc1, testbed, ftd1_ssh, ftd2_ssh, ftdha_ipv4, utility1)

    @aetest.subsection
    def clone_pcap_files(self):
        try:
            log.info("Cloning Pcaps Repository in Test Case Directory")
            os.system("rm -rf {}/eve_test_pcaps".format(base_dir))
            os.chdir("{}".format(base_dir))
            os.system("git clone {0} -b {1}".format(EVE_test_cases_data['git_info']['clone_url'],
                                                    EVE_test_cases_data['git_info']['clone_branch']))
        except Exception as e:
            self.failed("failed to Clone Pcap Files: {}".format(e))

class CommonEve:
    ##################################################################################################################
    # FUNCTION NAME: create_AC_Policy(self, api_service_fmc1: APIService, Ac_Policy_Config, device):                 #
    # DESCRIPTION  : Creating Access Policy                                                                          #
    # ARGUMENTS    : APIService - Object of the APIservice                                                           #
    #                device - Keyword of device(FTD1) for validating the events in FMC                               #
    #                Ac_Policy_Config - Object of AC policy                                                          #
    # RETURN VALUE : True - if AC Policy is created Successfully.                                                    #
    #                False - if AC policy creation got Failed.                                                       #
    ##################################################################################################################
    def create_AC_Policy(self, api_service_fmc1: APIService, Ac_Policy_Config, device):
        try:
            ac_policy = api_service_fmc1.create(Ac_Policy_Config)
            log.info('***** Successfully created AC policy *****')
            ac_policy_assignment = PolicyAssignment()
            ac_policy_assignment.targets = [device]
            ac_policy_assignment.policy = ac_policy
            api_service_fmc1.create(ac_policy_assignment)
            log.info('***** Successfully assigned AC policy to the FTD *****')
            return  True
        except Exception as e:
            log.info("Error while Creating Access Policy - {}".format(e))
            return False
    ##################################################################################################################
    # FUNCTION NAME: create_AC_Policy_with_file_and_intrusion(self, api_service_fmc1: APIService, Ac_Policy_Config,  #
    #                   File_Policy_Config: FilePolicy, Intrusion_Policy_Config:IntrusionPolicy,device):             #
    # DESCRIPTION  : Creating Access Policy with file and intrusion policy                                           #
    # ARGUMENTS    : APIService - Object of the APIservice                                                           #
    #                device - Keyword of device(FTD1) for validating the events in FMC                               #
    #                File_Policy_Config: FilePolicy - Object of File Policy                                          #
    #                Intrusion_Policy_Config: IntrusionPolicy - Object of Intrusion Policy                           #
    # RETURN VALUE : True - if AC Policy is created Successfully.                                                    #
    #                False - if AC policy creation got Failed.                                                       #
    ##################################################################################################################
    def create_AC_Policy_with_file_policy(self, api_service_fmc1: APIService, Ac_Policy_Config, File_Policy_Config: FilePolicy,device):
        try:
            file = api_service_fmc1.create(File_Policy_Config)
            file_policy = api_service_fmc1.find_one(IntrusionPolicy,
                                                   lambda policy: policy.name == File_Policy_Config.name)
            Ac_Policy_Config.rules[0].filePolicy = file_policy
            ac_policy = api_service_fmc1.create(Ac_Policy_Config)
            log.info('***** Successfully created AC policy *****')
            ac_policy_assignment = PolicyAssignment()
            ac_policy_assignment.targets = [device]
            ac_policy_assignment.policy = ac_policy
            api_service_fmc1.create(ac_policy_assignment)
            log.info('***** Successfully assigned AC policy to the FTD *****')
            return True
        except Exception as e:
            log.info("Error while Creating Access Policy - {}".format(e))
            return False

    def traffic_validation(self,testbed):
        log.info("Start system support debug and initiate traffic")
        ftd_clish = get_cli_connection(testbed, device_label="sensor1")
        time.sleep(5)
        ftd_clish.go_to('sudo_state')
        ftd_clish.sendline("echo "" > /ngfw/var/log/messages")
        ftd_clish.execute('echo \"\" > /ngfw/var/log/messages')
        time.sleep(10)
        client_ip = ''
        server_ip = ''
        try:
            d = Dialog([
                ['Enable firewall-engine-debug', 'sendline(y)', None, True, False],
                ['Please specify an IP protocol:', 'sendline({})'.format("tcp"), None, True,
                 False],
                ['Please specify a client IP address:', 'sendline({})'.format(client_ip), None, True,
                 False],
                ['Please specify a client port:', 'sendline()', None, True, False],
                ['Please specify a server IP address:', 'sendline({})'.format(server_ip), None, True,
                 False],
                ['Please specify a server port:', 'sendline()', None, True, False],
                ['Monitoring application identification and firewall debug messages.*', 'sendline()', None,
                 False, False]
            ])

            command = "system support application-identification-debug"

            ftd_clish.run_cmd_dialog(command, d, target_state='fireos_state', timeout=120)
            log.info("\n System support trace started successfully \n")
            return True

        except Exception as e:
                 log.error(e)
            log.info("Unable to start System support application-identification-debug")
            return False

    def create_AC_Policy_with_intrusion_policy(self, api_service_fmc1: APIService, Ac_Policy_Config,
                                                 Intrusion_Policy_Config:IntrusionPolicy,device):
        try:
            intrusion = api_service_fmc1.create(Intrusion_Policy_Config)
            intrusion_policy = api_service_fmc1.find_one(IntrusionPolicy,
                                                    lambda policy: policy.name == Intrusion_Policy_Config.name)

            Ac_Policy_Config.rules[0].ipsPolicy = intrusion_policy
            ac_policy = api_service_fmc1.create(Ac_Policy_Config)
            log.info('***** Successfully created AC policy *****')
            ac_policy_assignment = PolicyAssignment()
            ac_policy_assignment.targets = [device]
            ac_policy_assignment.policy = ac_policy
            api_service_fmc1.create(ac_policy_assignment)
            log.info('***** Successfully assigned AC policy to the FTD *****')
            return True
        except Exception as e:
            log.info("Error while Creating Access Policy - {}".format(e))
            return False
    ##################################################################################################################
    # FUNCTION NAME: show_snort_counters_eve_exempted(self, ftd_shell,hint):                                         #
    # DESCRIPTION  : Verifying the Snort counters                                                                    #
    # ARGUMENTS    : ftd_shell - SSH Object of FMC                                                                   #
    #                hint - Variable to define the VPN Name                                                          #
    # RETURN VALUE : True - if snort counter got increased.                                                          #
    #                False - if snort counter not increased.                                                         #
    ##################################################################################################################
    def show_snort_counters_eve_exempted(self, ftd_shell,hint):
        ftd_shell.conn.go_to('fireos_state')
        if hint == 'surfshark vpn:':
            cmd_output = ftd_shell.conn.execute('show snort counters | begin vpn')
            exempted = re.search(r'surfshark vpn:\s*(\d+)', cmd_output)

        elif hint == "malware-drivepack:":
            cmd_output = ftd_shell.conn.execute('show snort counters | begin malware-drivepack')
            exempted = re.search(r'malware-adware:\s*(\d+)', cmd_output)

        else:
            cmd_output = ftd_shell.conn.execute('show snort counters | begin tor')
            exempted = re.search(r'tor:\s*(\d+)', cmd_output)
            if exempted:
                return True
            else:
                return False
        try:
            if exempted:
                exempted_count = int(exempted.group(1))
                log.info("exempted_count : {}".format(exempted_count))
                if exempted_count > 0:
                    return True
            else:
                return False
        except:
            log.info('{} is causing assertion error message'.format('show_snort_counters_command_output_collection'))
    ##################################################################################################################
    # FUNCTION NAME: check_fmc_connection_events_and_fingerprint(self, fmc,events_dict,Flag):                        #
    # DESCRIPTION  : Verifying the Events in FMC                                                                     #
    # ARGUMENTS    : fmc - Object of Config Provider                                                                 #
    #                events_dict - Dictionay of events to verify                                                     #
    #                 Flag: - Boolean variable                                                                       #
    # RETURN VALUE : count = 1 - if Events got Verified.                                                             #
    #                count = 0 - if Events not generated.                                                            #
    ##################################################################################################################
    def check_fmc_connection_events_and_fingerprint(self, fmc,events_dict,Flag):
        events = Events(fmc, event_type=EventsTypes.connection.value)
        # events.field_selector(field=ConnectionEventsFilters.tlsfp.value)
        if Flag == 'False':
            sample = [ConnectionEventsFilters.action,
                      ConnectionEventsFilters.access_control_policy
                      ]
        else:
            sample = [ConnectionEventsFilters.action,
                      ConnectionEventsFilters.access_control_policy,
                      ConnectionEventsFilters.tlsfp_malware_confidence,
                      ConnectionEventsFilters.tlsfp_process_name,
                      ConnectionEventsFilters.other_enrichment
                      ]
        for req in sample:
            events.field_selector(field=req.value)
        result = events.search()
        log.info('result search {} '.format(result))
        count = 0
        values_list = result['VALUES']
        events_set = set(events_dict.values())
        result = any(events_set.issubset(set(sublist)) for sublist in values_list)
        if result and Flag == 'True':
            count = 1
            return True
        else:
            return False
    ##################################################################################################################
    # FUNCTION NAME: get_latest_partition(self, event_type,fmc_ssh)                                                  #
    # DESCRIPTION  : Verifying the Events Database in FMC                                                            #
    # ARGUMENTS    : fmc_ssh - SSH Object of FMC                                                                     #
    #                event_type - type of event to verify                                                            #
    # RETURN VALUE : sorted(parts['VALUES'])[-1][0] - Table Name                                                     #
    ##################################################################################################################
    def get_latest_partition(self, event_type,fmc_ssh):
        try:
            EVENT_TYPES = {'connection': {'db': 'eventdb', 'db_table': 'connectionevent'}}
            parts = fmc_ssh.execute_omniquery(
                "show tables like '{}_1%';".format(EVENT_TYPES[event_type]['db_table']), EVENT_TYPES[event_type]['db'])
            if len(parts['VALUES']) == 0:
                log.warn("No partitions found for event type {} tables {}".format(
                    event_type, EVENT_TYPES[event_type]['db_table']))
            else:
                return sorted(parts['VALUES'])[-1][0]
        except Exception as e:
            log.info(e)
    ##################################################################################################################
    # FUNCTION NAME: verify_enrichment_fields(self,fmc_ssh,edj_field, me_field):                                     #
    # DESCRIPTION  : Verifying the Fields in ConnectionEvent table                                                   #
    # ARGUMENTS    : fmc_ssh - SSH Object of FMC                                                                     #
    #                edj_field - value to verify                                                                     #
    #                me_field - field to verify                                                                      #
    # RETURN VALUE : True - if value is present in the table                                                         #
    #                False - if value is not  present in the table                                                   #
    ##################################################################################################################
    def verify_enrichment_fields(self,fmc_ssh,edj_field, me_field,other_enr):
        try:
            event_type = 'connection'
            table = CommonEve().get_latest_partition(event_type,fmc_ssh)
            event_field = "enrichmentdatajson, mitreenrichment, otherenrichment"
            database = 'eventdb'
            output = fmc_ssh.execute_omniquery("select {} from {};".format(event_field, table), database)
            log.info("--------------------------------------------------")
            log.info("**************************************************")
            log.info(output)
            key=0
            for value in output['VALUES']:
                if edj_field and me_field and other_enr in value:
                    key=1
                elif edj_field and (me_field or other_enr) in value:
                    key=1
            if key == 1:
                assert True, "Tag Verification Passed!!"
                return True
            else:
                return False
        except Exception as e:
            log.info(e)
    ##################################################################################################################
    # FUNCTION NAME: verify_map_file(self,ftd_1ssh, file_name):                                                      #
    # DESCRIPTION  : Verifying the Snort counters                                                                    #
    # ARGUMENTS    : ftd1_ssh - SSH Object of FTD1                                                                   #
    #                file_name - File name to be verified                                                            #
    # RETURN VALUE : True - if File is present                                                                       #
    #                False - if File is not present.                                                                 #
    ##################################################################################################################
    def verify_map_file(self,ftd_1ssh, file_name):
        ftd_1ssh.conn.go_to('expert_state')
        ftd_1ssh.conn.go_to('sudo_state')
        ftd_1ssh.conn.execute('cd /ngfw/var/sf/vdb/active-version')
        file_list = ftd_1ssh.conn.execute('ls')
        log.info(file_list)
        time.sleep(10)
        if file_name in file_list:
            return True
        else:
            return False
    ##################################################################################################################
    # FUNCTION NAME: purge_selected_events(self, api_service_fmc1: APIService, data_purge):                          #
    # DESCRIPTION  : Deleting the Events in the FMC page                                                             #
    # ARGUMENTS    : api_service_fmc1: APIService - Object of APIService                                             #
    #                data_purge - Object of DataPurge                                                                #
    # RETURN VALUE : NA                                                                                              #
    ##################################################################################################################
    def purge_selected_events(self, api_service_fmc1: APIService, data_purge):
        log.info(f'we are in DeleteEvents function\n\n')
        try:
            api_service_fmc1.delete(data_purge)
        except Exception as e:
            log.error('The following error occurred while deleting events {}'.format(e))
    ##################################################################################################################
    # FUNCTION NAME: verify_exempted_events(self,fmc1, events_dict, Flag):                                           #
    # DESCRIPTION  : Polling the Events in the FMC page                                                              #
    # ARGUMENTS    : fmc1: Object of FMC                                                                             #
    #                events_dict: Dict of events to verify                                                           #
    # RETURN VALUE : True - if Events captured                                                                       #
    #                False - if Events not captured                                                                  #
    ##################################################################################################################
    def verify_exempted_events(self,fmc1, events_dict, Flag):
        log.info("polling started")
        try:
            if polling.poll(lambda: self.check_fmc_connection_events_and_fingerprint(fmc1, events_dict, Flag) is True, step=15, timeout=180):
                log.info("event found polling ended")
                return True
        except Exception as e:
            pass
            log.info("polling time out")
            return False
    ##################################################################################################################
    # FUNCTION NAME:pcap_replay(self, api_service_fmc1: APIService, endpoint1_ssh, pcap_path, pcap_name, ftd_shell,  #
    #                                                              data_purge):                                      #
    # DESCRIPTION  : Passing the PCAP Replay traffic from Endpoint                                                   #
    # ARGUMENTS    : ftd_shell - SSH Object of FMC                                                                   #
    #                api_service_fmc1: APIService - Object of APIService                                             #
    #                data_purge - Object of DataPurge                                                                #
    #                pcap_path - Path of the pcap file                                                               #
    #                pcap name - Name of the pcap file                                                               #
    #                endpoint1_ssh - SSH object of endpoint-1                                                        #
    # RETURN VALUE : NA                                                                                              #
    ##################################################################################################################
        def pcap_replay(self, api_service_fmc1: APIService, endpoint1_ssh, endpoint2_ssh, pcap_path, pcap_name, ftd_shell, data_purge):
            ep_path = "/root/eve_pcap"
        path = "{}/{}".format(pcap_path, pcap_name)
        log.info("copying pcap file from {} to device {}".format(path, ep_path))
        endpoint1_ssh.conn.execute("mkdir -p {}".format(ep_path))
        endpoint1_ssh.copy_from_container_to_device(path, ep_path)
        ftd_shell.conn.go_to('fireos_state')
        ftd_shell.conn.execute('clear snort counters')
        ftd_shell.conn.execute('clear conn')
        self.purge_selected_events(api_service_fmc1, data_purge)
        ep2_mac = endpoint2_ssh.conn.execute("ifconfig eth1 | grep -o 'ether [[:xdigit:]:]\{17\}' | awk '{print $2}'")
        new_pcap = "newly_generated_mac.pcap"
        endpoint1_ssh.conn.execute('cd /root/eve_pcap')
        new_pcap_cmd = "tcprewrite --infile {} --outfile {}  --enet-dmac={}".format(pcap_name, new_pcap, ep2_mac)
        endpoint1_ssh.conn.execute(new_pcap_cmd)
        time.sleep(15)
        # tcpreplay_cmd = "tcpreplay --intf1=eth1 --topspeed {}/{}".format(ep_path, new_pcap)
        tcpreplay_cmd = "tcpreplay-edit --mtu-trunc --intf1=eth1 --topspeed {}/{}".format(ep_path, new_pcap)
        endpoint1_ssh.conn.execute(tcpreplay_cmd)
        # endpoint1_ssh.conn.execute("rm -rf {}".format(ep_path))

@aetest.loop(mitre_test_case=list(mitre_test_cases.keys()))
class EVE_TestCase(aetest.Testcase):
    @aetest.setup
    def set_feature(self):
        set_testcase_feature([Features76.feature30.value])
        set_tims_testcase("Txw16238197c,Txw16238198c,Txw16238199c,Txw16238200c,Txw16238201c,Txw16238205c,Txw16238206c,Txw16238208c,Txw16238209c,Txw16238210c,Txw16238211c,Txw16238212c,Txw16238213c,Txw16238214c,Txw16238215c")
    @aetest.test
    def Mitre_test(self, steps, mitre_test_case, api_service_fmc1: APIService,fmc1, data_purge, endpoint1_ssh, endpoint2_ssh, eve_SRU_Ac_config,
                   ftd1_ssh,fmc_ssh,device ,ssl_Ac_Policy,eve_enabled_AC_Policy,mitre_tags,eve_si_ac_policy_config,current_version,
                   ac_test_intrusion_Policy,ac_test_file_Policy,intrusion_policy_config,file_policy_config,testbed,appid_trust_policy_config,
                   app_block_policy_config,ac_policy_mitre_config,ac_policy_flow_allow_block,vdb_access_policy_config,ac_backup_restore_config,
                   client_ip_address,server_ip_address,encrypted_dns_Ac_Policy_config):
        sec=120
        mitre_test = mitre_test_cases[mitre_test_case]
        edj_field = mitre_test['edj_field']
        me_field = mitre_test['me_field']
        other_enr = mitre_test['other_enr']
        File_name= 'enrichment_map'
        mitre_pcap = mitre_test['pcap_name']
        pcap_path = mitre_test['pcap_path']
        current_version = float(current_version[:3])
        log.info(current_version)
        for pcap in mitre_pcap:
            Flag = 'True'
            if "AC_policy_ubuntu_tor_tor_org" == mitre_test_case and mitre_test_case in mitre_tags:
                # time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 ac_policy_mitre_config.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1, ac_policy_mitre_config, device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    ftd_clish = get_cli_connection(testbed, device_label="sensor1")
                    ftd_clish.disconnect()
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'tor:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "AC_policy_with_encrypted_dns" == mitre_test_case:
                with steps.start("Create Access Policy"):
                    ret_val = CommonEve().create_AC_Policy(api_service_fmc1,encrypted_dns_Ac_Policy_config,device)
                    if not ret_val:
                        self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir,pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint='surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh,hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events ang Encrypted Tag Captured {} as Expected".format(ret_val))
                time.sleep(60)

            elif "AC_policy_with_ssl" == mitre_test_case:
                # time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ret_val = CommonEve().create_AC_Policy(api_service_fmc1,ssl_Ac_Policy,device)
                    if not ret_val:
                        self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir,pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint='surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh,hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                      events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "AC_policy_with_tsid" == mitre_test_case:
                interface = mitre_test['interface']
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 eve_enabled_AC_Policy.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1,eve_enabled_AC_Policy,device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Verify the Mapping file"):
                    res = CommonEve().verify_map_file(ftd1_ssh,File_name)
                    if res:
                        log.info("Mapping file is present in the desired location")
                    else:
                        self.failed("Mapping File is not present")

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                # with steps.start("Running the traffic using Aquila-Replay in client and server"):
                #     EVE_utils().Aquila_replay(ftd1_ssh,endpoint1_ssh,endpoint2_ssh,api_service_fmc1, data_purge,base_dir, pcap_path,pcap,client_ip_address,server_ip_address,interface)

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        log.info("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    # ret_val = CommonEve().check_fmc_connection_events_and_fingerprint(fmc1, events_dict, Flag)
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "AC_Policy_with EVE_Enable" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 eve_enabled_AC_Policy.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1,eve_enabled_AC_Policy,device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "AC_Policy_with EVE_Disable" == mitre_test_case:
                Flag = 'False'
                with steps.start("Do the pcap replay"):
                    CommonFunction().change_eve_state_and_verify(eve_enabled_AC_Policy.name,api_service_fmc1,state=False)
                    log.info("Disabling EVE Successful")
                    EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is not increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        if not ret_val and Flag == 'False':
                            log.info("Exempt counter not increased due to Disabled EVE")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag = 'False')
                    if ret_val == False and Flag == 'False':
                        log.info("Events are Empty due to Disable Eve")
                    elif ret_val == False and Flag != 'False':
                        log.info("Events are Empty!!")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if not events_log:
                        log.info("Collecting Mitre Tag not verified due to Eve Disable")

            elif "Intrusion_policy" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ret_val = CommonEve().create_AC_Policy_with_intrusion_policy(api_service_fmc1, ac_test_intrusion_Policy,intrusion_policy_config, device)
                    if not ret_val:
                        self.failed('Ac Policy with File and Intrusion policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                             if wget_ret_val:
                            log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "File_policy" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ret_val = CommonEve().create_AC_Policy_with_file_policy(api_service_fmc1, ac_test_file_Policy, file_policy_config, device)
                    if not ret_val:
                        self.failed('Ac Policy with File and Intrusion policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "VDB_Downgrade" == mitre_test_case or "VDB_Upgrade" in mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 vdb_access_policy_config.name)
                    if ac_policy is None:
                        ret_val = EVE_utils().create_access_policy(api_service_fmc1, device, vdb_access_policy_config)
                        if not ret_val:
                            self.failed("AC Policy creation failed")
                EVE_utils().deploy_all(api_service_fmc1, device)

                if "VDB_Downgrade" == mitre_test_case:
                    with steps.start("Creating dummy AC Rules"):
                        EVE_utils().create_multiple_rules(api_service_fmc1, vdb_access_policy_config, EVE_test_cases_data,
                                                          device)
                        log.info("Successfully created dummy AC Rules")

                with steps.start("Enabling the Application-Debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

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

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "Snort_Toggle" == mitre_test_case:

                if current_version < 7.7:
                    with steps.start("Create Access Policy"):
                        ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                     eve_enabled_AC_Policy.name)
                        if ac_policy is None:
                            ret_val = CommonEve().create_AC_Policy(api_service_fmc1, eve_enabled_AC_Policy, device)
                            if not ret_val:
                                self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                    EVE_utils().deploy_all(api_service_fmc1, device)

                    with steps.start("Enabling the Application-debug"):
                        ret_val = CommonEve().traffic_validation(testbed)
                        if not ret_val:
                            log.info("Traffic validation has failed")
                        else:
                            log.info("Traffic validation is successfull")

                    with steps.start("Do the pcap replay"):
                        file_name = pcap
                        file_path = "{}/{}".format(base_dir, pcap_path)
                        CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                    with steps.start("Veryfying the Fingerprints"):
                        wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                        if wget_ret_val:
                            log.info("fingerprints are generated")
                        else:
                            self.failed("fingerprints are not generated")

                    with steps.start("Toggle snort 3 to snort 2"):
                        if not CommonFunction().toggle_snort(ftd1_ssh, device, api_service_fmc1):
                            self.failed('Error During Snort Toggle, Aborting')
                        else:
                            log.info("Deploy Toggle Changes")
                            EVE_utils().deploy_all(api_service_fmc1, device)

                    with steps.start("Collecting Mitre Tag:"):
                        events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                        if not events_log:
                            log.info("Collecting Mitre Tag not verified due to Snort Toggle!!")
                    with steps.start("Toggle snort 2 to snort 3"):
                        if not CommonFunction().toggle_snort(ftd1_ssh, device, api_service_fmc1):
                            self.failed('Error During Snort Toggle, Aborting')
                        else:
                                         log.info("Deploy Toggle Changes")
                            EVE_utils().deploy_all(api_service_fmc1, device)
                else:
                    log.info("Got skipped due to FMC version is 7.7")

            elif "AC_Policy_with_Trust_APPID" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 appid_trust_policy_config.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1, appid_trust_policy_config, device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        log.info("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            log.info("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "AC_Policy_with_Block_APPID" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 app_block_policy_config.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1, app_block_policy_config, device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "AC_Policy_with_Flow_Allow_Block" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ret_val = CommonEve().create_AC_Policy(api_service_fmc1,ac_policy_flow_allow_block, device)
                    if not ret_val:
                        self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")
                time.sleep(sec)

                with steps.start("Blocking the Traffic and checking Mitre attack is happened or not"):
                    ac_pol = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 ac_policy_flow_allow_block.name)
                    advanced_fragment = api_service_fmc1.find_one_by_record(
                        AdvancedAccessPolicyFragment(), container_id=ac_pol.id)
                    advanced_fragment.eve_settings.blockThreshold = 0
                    api_service_fmc1.update(advanced_fragment.eve_settings, container_id=ac_pol.id)
                    advanced_fragment = api_service_fmc1.find_one_by_record(AdvancedAccessPolicyFragment(),
                                                                           container_id=ac_pol.id)
                    assert advanced_fragment.eve_settings.blockThreshold is 0, "EVE Setting was updated correctly"
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Application-Debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                 with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    events_dict['Action'] = "Block"
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "Ac_Policy_SRU_GEO_update" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 eve_SRU_Ac_config.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1, eve_SRU_Ac_config, device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Update SRU"):
                    site='bgl'
                    sru = SruUpdate(fmc_ssh,site)
                    try:
                        result = sru.update()
                        if result:
                            log.info("SRU was updated")
                        else:
                            log.info("SRU was NOT updated")
                    except Exception as e:
                        self.failed(e)

                with steps.start("Enabling the Application-Debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    events_dict['Action'] = "Block"
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "Ac_Policy_Backup_and_Restore_FMC" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 ac_backup_restore_config.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1, ac_backup_restore_config, device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Do the Backup"):
                    backup_payload = BackupOptions(include_config=True, include_events=False, include_tid=False)
                    backup_restore = BackupRestore(fmc1, polling_max_timeout=1200)
                    backup_name = "Mitre_fmc_backup_restore"
                    archive_path = backup_restore.backup_fmc(backup_name, backup_options=backup_payload,
                                                             backup_timeout=1200)
                    self.parent.parameters.update(fmc_config_path=archive_path)
                    log.info(archive_path)
                    if archive_path is None:
                        log.info("Error while Backing up FMC!")
                    else:
                        log.info("Successfully Backed up FMC")
                    time.sleep(60)

                with steps.start("Do the Restore"):
                    archive_path = self.parent.parameters['fmc_config_path']
                    try:
                        backup_restore = BackupRestore(fmc1, polling_max_timeout=1200)
                        backup_restore.restore_fmc(archive_path, restore_options=BackupOptions(include_config=True,
                                                                                               include_events=False,
                                                                                               include_tid=False))
                        log.info("Successfully Restored FMC!!")
                    except Exception as e:
                        pass
                minutes = 9
                time.sleep(minutes * 60)
                ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                             eve_enabled_AC_Policy.name)
                if ac_policy is None:
                    log.info("Restore failed!!")

                with steps.start("Enabling the Application-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if events_log:
                        log.info("Collecting Mitre Tag passed!!")
                    else:
                        self.failed("Collecting Mitre Tag failed!!")

            elif "Ac_Policy_SI_Enabled_AC_Policy" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Create Access Policy"):
                    ac_policy = api_service_fmc1.find_one(AccessPolicy, condition=lambda policy: policy.name ==
                                                                                                 eve_si_ac_policy_config.name)
                    if ac_policy is None:
                        ret_val = CommonEve().create_AC_Policy(api_service_fmc1, eve_si_ac_policy_config, device)
                        if not ret_val:
                            self.failed('AC Policy Creation failed, Aborting', goto=["common_cleanup"])
                EVE_utils().deploy_all(api_service_fmc1, device)

                with steps.start("Enabling the Applicatio-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name, ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exemt counter got increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field,other_enr)
                    if not events_log:
                        self.passed("Collecting Mitre Tag Failed!!!")
                    else:
                        log.info("Collecting Mitre Tag passed!!")

            elif "Ac_policy_with_mitre_block" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Enabling the Applicatio-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name,
                                            ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'malware-drivepack:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            log.info("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exemt counter got increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field, other_enr)
                    if not events_log:
                        self.failed("Collecting Mitre Tag Failed!!")
                    else:
                        log.info("Collecting Mitre Tag passed!!")

            elif "AC_policy_shurfshark" == mitre_test_case:
                time.sleep(sec)
                with steps.start("Enabling the Applicatio-debug"):
                    ret_val = CommonEve().traffic_validation(testbed)
                    if not ret_val:
                        log.info("Traffic validation has failed")
                    else:
                        log.info("Traffic validation is successfull")

                with steps.start("Do the pcap replay"):
                    file_name = pcap
                    file_path = "{}/{}".format(base_dir, pcap_path)
                    CommonEve().pcap_replay(api_service_fmc1, endpoint1_ssh, endpoint2_ssh, file_path, file_name,
                                            ftd1_ssh, data_purge)

                with steps.start("Veryfying the Fingerprints"):
                    wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                    if wget_ret_val:
                        log.info("fingerprints are generated")
                    else:
                        self.failed("fingerprints are not generated")

                if current_version < 7.7:
                    with steps.start("verify snort counter is increased for Mitre pcap"):
                        hint = 'surfshark vpn:'
                        ret_val = CommonEve().show_snort_counters_eve_exempted(ftd1_ssh, hint)
                        if not ret_val and Flag == 'True':
                            self.failed("ERROR: Exempt counter not increased")
                        else:
                            log.info("Exempt counter got increased")

                with steps.start("Validation of Unified Events in FMC"):
                    events_dict = mitre_test['events']
                    ret_val = CommonEve().verify_exempted_events(fmc1, events_dict, Flag)
                    if not ret_val:
                        log.info("Events are Empty")
                    else:
                        log.info("Events Captured {} as Expected".format(ret_val))
                time.sleep(60)

                with steps.start("Collecting Mitre Tag:"):
                    events_log = CommonEve().verify_enrichment_fields(fmc_ssh, edj_field, me_field, other_enr)
                    if not events_log:
                        self.failed("Collecting Mitre Tag Failed!!")
                    else:
                        log.info("Collecting Mitre Tag passed!!")

class PreCleanUp(aetest.Testcase):
    @aetest.setup
    def set_feature(self):
        set_testcase_feature([Features76.feature30.value])
        set_tims_testcase("Txw16238215c")
    @aetest.test
    def break_ha(self, api_service_fmc1, ftdha_ipv4, utility1, ha_name):
        ftdha_to_break = api_service_fmc1.find_one(HighAvailability, lambda ftdha_object: ftdha_object.name == ha_name)
        if ftdha_to_break is not None:
            CommonFunction().break_ha(api_service_fmc1, ftdha_ipv4, utility1)
            log.info("Break HA Successful ")

class CommonCleanup(ftltest.CommonCleanup):
    groups = ['common', 'CommonCleanup']

if __name__ == '__main__':
    data_file_path = os.path.dirname(__file__) + '/data/mitre-data.yaml'
    aetest.main(datafile=data_file_path)




                      