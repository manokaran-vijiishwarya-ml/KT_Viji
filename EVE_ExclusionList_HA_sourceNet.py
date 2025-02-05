import time
import os
import polling
from ats import aetest
import logging
from lib.models.deploy.model import DeploymentRequest
from lib.models.devices.device_management.device.inline_sets.inline_set.model import InlineSet
from lib.models.devices.device_management.high_availability.constants import UpdateHAActions
from lib.models.devices.device_management.high_availability.model import HighAvailability
from lib.models.devices.device_management.device.interfaces.physical_interface.model import PhysicalInterface
from lib.models.fragments.inline_pairs.model import InlinePairsFragment

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
from lib.features_constants import Features76, Features77
from lib.utils.functions import set_testcase_feature, set_tims_testcase
from tests.feature.ftd.tests.EVE.Mitre_Test import CommonEve


DATA_PATH = 'data/Eve_ExclusionList_HA_sourceNet.yaml'
base_dir = os.path.dirname(__file__)
test_file_path = ["{}/{}".format(base_dir, DATA_PATH), __file__]
EVE_test_cases_data = yaml.safe_load(Path(test_file_path[0]).read_text())
EVE_test = EVE_test_cases_data['EVE_test_cases']
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

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
        source_ipv6= '2001:1::1:123'
        cmd = "sed -i 's/1.1.1.1/{}/g' /etc/bind/named.eve.com".format(inside_host_ip)
        cmd_v6= "sed -i 's/2001:1::2:109/{}/g' /etc/bind/named.eve.com".format(source_ipv6)
        endpoint2.conn.execute(cmd, timeout=2)
        endpoint2.conn.execute(cmd_v6, timeout=2)
        log.info("updating dns and search domain in EP2")
        cmd = "echo nameserver {} > /etc/resolv.conf".format(dns_server_ip)
        cmd1 = "echo search eve.com >> /etc/resolv.conf"
        endpoint2.conn.execute(cmd, timeout=20)
        endpoint2.conn.execute(cmd1, timeout=20)

        result = endpoint2.conn.execute(cmd="cat /etc/resolv.conf", timeout=20)
        cmd = 'systemctl restart named'
        endpoint2.conn.execute(cmd, timeout=5)

        # security_zone = store.get("file:{}".format(self.args.data_file[0]),
        #                           root_object='security_zones.subint_security_zones{}'.format(1))
        ps_policy_config = store.get("file:{}".format(self.args.data_file[0]),
                                     root_object='platform_settings_policy.create')

        ps_policy_config.dns.MultiDNSServerGroupsTable[0].MultiDnsServerGroupName.dnsservers = [dns_server_ip]

        self.parent.parameters.update({
            'inlineset_config': store.get("file:{}".format(self.args.data_file[0]),
                                          root_object='inline_set.test_rest_inlineset'),
            "EVE_block_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                 root_object="access_policies.EVE_block_policy"),
            "EVE_exempt_src_host_ipv4_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                root_object="access_policies.EVE_exempt_source_host_ipv4_policy"),
            "EVE_exempt_src_host_ipv6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                root_object="access_policies.EVE_exempt_source_host_ipv6_policy"),
            "EVE_exempt_source_network_ipv4_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                      root_object="access_policies.EVE_exempt_source_network_ipv4_policy"),
            "EVE_exempt_source_network_ipv6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                      root_object="access_policies.EVE_exempt_source_network_ipv6_policy"),
            "EVE_exempt_range_source_ipv4_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                    root_object="access_policies.EVE_exempt_range_source_ip4_policy"),
            "EVE_exempt_range_source_ipv6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                    root_object="access_policies.EVE_exempt_range_source_ipv6_policy"),
            "EVE_exempt_src_fqdnv4_policy_no_dns_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                    root_object="access_policies.EVE_exempt_src_fqdnv4_policy_no_dns"),
            "EVE_exempt_src_fqdnv4_policy_invalid_domain_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                            root_object="access_policies.EVE_exempt_src_fqdnv4_policy_invalid_domain"),
            "EVE_exempt_src_fqdnv4_policy_dns_not_reachable_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                               root_object="access_policies.EVE_exempt_src_fqdnv4_policy_not_reachable"),
            "EVE_exempt_src_fqdnv4_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                             root_object="access_policies.EVE_exempt_src_fqdnv4_policy"),
            "EVE_exempt_src_fqdnv6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                             root_object="access_policies.EVE_exempt_src_fqdnv6_policy"),
            "EVE_exempt_src_fqdnv4v6_policy_config": store.get("file:{}".format(self.args.data_file[0]),
        root_object="access_policies.EVE_exempt_src_fqdnv4v6_policy"),
             "src_fqdn_unique_object_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                     root_object='access_policies.src_fqdn_unique_object_AC_policy'),
            "src_fqdn_common_object_access_policy_config": store.get("file:{}".format(self.args.data_file[0]),
                                                                     root_object='access_policies.src_fqdn_common_object_AC_policy'),
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
            "base_dir": base_dir
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

        primary_device = api_service_fmc1.find_one(Device,condition=lambda
                                                       device_obj: device_obj.name == ftd1_ssh.device_ip)
        secondary_device = api_service_fmc1.find_one(Device,condition=lambda
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
################################################
class commonSourceNet:

    def purge_selected_events(self, api_service_fmc1: APIService, data_purge):
        log.info(f'we are in DeleteEvents function\n\n')
        try:
            api_service_fmc1.delete(data_purge)
        except Exception as e:
            self.failed('The following error occurred while deleting events {}'.format(e))

    def pcap_replay(self, api_service_fmc1: APIService, endpoint1_ssh, pcap_path, pcap_name, ftd_shell, data_purge):
        ep_path = "/root/eve_pcap/"
        path = "{}/{}".format(pcap_path, pcap_name)
        log.info("copying pcap file from {} to device {}".format(path, ep_path))
        endpoint1_ssh.conn.execute("mkdir -p {}".format(ep_path))
        endpoint1_ssh.copy_from_container_to_device(path, ep_path)
        ftd_shell.conn.execute('clear snort counters')
        ftd_shell.conn.execute('clear conn')
        self.purge_selected_events(api_service_fmc1, data_purge)
        pcap_path = "cd {}".format(ep_path)
        endpoint1_ssh.conn.execute(pcap_path)
        tcprewrite_cmd = "tcprewrite --infile={}/{} --outfile=output.pcap --srcipmap=10.12.10.101:172.16.2.1".format(ep_path, pcap_name)
        print(tcprewrite_cmd)
        endpoint1_ssh.conn.execute(tcprewrite_cmd)
        tcpreplay_cmd = "tcpreplay --intf1=eth1 --topspeed {}/output.pcap".format(ep_path)

        endpoint1_ssh.conn.execute(tcpreplay_cmd)

#########################################################
@aetest.loop(FQDN_test_case=list(EVE_test.keys()))
class FQDN_Testcases(aetest.Testcase):

    @aetest.setup
    def set_feature(self):
        set_testcase_feature([Features76.feature44.value])
        set_tims_testcase("Txw16179267c, Txw16179269c")

    @aetest.test
    def eve_test_cases(self, steps, FQDN_test_case, api_service_fmc1, utility_eve, ftd1_ssh, fmc1, testbed, device,
                       EVE_exempt_src_fqdnv4_policy_no_dns_config,
                       EVE_exempt_src_fqdnv4_policy_invalid_domain_config,EVE_exempt_src_fqdnv4_policy_dns_not_reachable_config, EVE_exempt_src_fqdnv4_policy_config,
                       EVE_exempt_src_fqdnv6_policy_config, ftd1_cli, endpoint1_ssh,
                       endpoint2_ssh,
                       data_purge,
                       EVE_exempt_src_fqdnv4v6_policy_config,
                       src_fqdn_unique_object_access_policy_config, ps_policy_config, ftd1_config,
                       src_fqdn_common_object_access_policy_config,
                       base_dir,
                       EVE_exempt_src_host_ipv4_policy_config, EVE_exempt_src_host_ipv6_policy_config,
                       EVE_exempt_source_network_ipv4_policy_config,
                       EVE_exempt_source_network_ipv6_policy_config, EVE_exempt_range_source_ipv4_policy_config,
                       EVE_exempt_range_source_ipv6_policy_config, EVE_block_policy_config):
        time.sleep(60)
        FQDN_test_name = EVE_test[FQDN_test_case]
        log.info("********** {}".format(FQDN_test_name))
        delay = 60
        if "Exception_with_Source_FQDN_V4_without_DNS" == FQDN_test_case:

            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
            with steps.start("Returning back from the sudo user"):
                ftd1_ssh.conn.go_to('fireos_state')
                ftd1_ssh.conn.execute("show snort counters")

            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_fqdnv4_policy_no_dns_config)
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

            with steps.start("Enabling the Application-debug"):
                ret_val = CommonEve().traffic_validation(testbed)
                if not ret_val:
                    log.info("Traffic validation has failed")
                else:
                    log.info("Traffic validation is successfull")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Verifying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
                    self.failed("fingerprints are not generated")

            with steps.start("verify snort counter is not increased for eve exempt due to DNS server not configured"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to not Configuring DNS server")

        elif "Exception_with_Source_FQDN_V4" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
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
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_fqdnv4_policy_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")
            time.sleep(10)
            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    self.failed("ERROR: DNS Host check failed")

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
                file_path = "{}/eve_test_pcaps".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
                    self.failed("fingerprints are not generated")

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

        elif "Exception_with_Source_FQDN_invalid_domain" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_fqdnv4_policy_invalid_domain_config)
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
                else:
                    self.failed("fingerprints are not generated")
                    # log.info("fingerprints are not generated")

            with steps.start("verify snort counter is not increased for eve exempt due to invalid domain"):
                ret_val = utility_eve.show_snort_counters_eve_exempted(ftd1_ssh)
                if not ret_val:
                    log.info("Exempt counter not increased due to invalid domain name")

            with steps.start("Verifying unified events in FMC is getting failed due to invalid domain"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to invalid domain")

        elif "Exception_with_Source_FQDN_dns_not_reachable" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_fqdnv4_policy_dns_not_reachable_config)
                if not ret_val:
                    self.failed("ERROR: AC Policy creation failed")

            with steps.start("Deactivating the DNS server"):
                endpoint2_ssh.conn.execute("systemctl stop named")
                time.sleep(10)
                res = endpoint2_ssh.conn.execute("systemctl status named")
                if "Stopped BIND Domain Name Server" in res:
                    log.info("DNS server Deactivated successfully")

            with steps.start("Checking DNS Host Address"):
                ret_val = utility_eve.dns_host_check(ftd1_ssh, hostname, ip_addr)
                if not ret_val:
                    log.info("ERROR: DNS server not reachable")

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
                time.sleep(10)
                res = endpoint2_ssh.conn.execute("systemctl status named")
                if "Started BIND Domain Name Server" in res:
                    log.info("DNS server Activated successfully")

            with steps.start("Verifying  of unified events in FMC is getting failed due to DNS server not configured"):
                ret_val = utility_eve.verify_exempted_events(fmc1)
                if not ret_val:
                    log.info("Validation of Unified Events in FMC failed due to not Configuring DNS server")


        elif "Exception_with_Source_FQDN_V6" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_fqdnv6_policy_config)
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
                else:
                    # log.info("fingerprints are not generated")
                    self.failed("fingerprints are not generated")

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


        elif "Exception_with_Source_FQDN_V4_V6" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_fqdnv4v6_policy_config)
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

            with steps.start("Enabling the Application-debug"):
                ret_val = CommonEve().traffic_validation(testbed)
                if not ret_val:
                    log.info("Traffic validation has failed")
                else:
                    log.info("Traffic validation is successfull")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
                    self.failed("fingerprints are not generated")

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

        elif "Exception_with_Source_FQDN_unique" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           src_fqdn_unique_object_access_policy_config)
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

            with steps.start("Enabling the Application-debug"):
                ret_val = CommonEve().traffic_validation(testbed)
                if not ret_val:
                    log.info("Traffic validation has failed")
                else:
                    log.info("Traffic validation is successfull")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
                    self.failed("fingerprints are not generated")

                ###take part in ftd ############
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

        elif "Exception_with_Source_FQDN_common" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            hostname = FQDN_test_name['dns_name']
            ip_addr = FQDN_test_name['address']
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           src_fqdn_common_object_access_policy_config)
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

            with steps.start("Enabling the Application-debug"):
                ret_val = CommonEve().traffic_validation(testbed)
                if not ret_val:
                    log.info("Traffic validation has failed")
                else:
                    log.info("Traffic validation is successfull")

            with steps.start("Do the pcap replay"):
                file_path = "{}/eve_test_pcaps/".format(base_dir)
                file_name = FQDN_test_name['pcap_file']
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)

            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
                    self.failed("fingerprints are not generated")

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

        elif "Getting_field_value" == FQDN_test_case:
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

        elif "Exception_with_Source_Host_IPV4" == FQDN_test_case:
            threat_score = threat_score[:2]
            log.info("Testcase: {}".format(FQDN_test_case))
            log.info("n/w object: {}".format(FQDN_test_name['dst_object']))
            log.info("pcap file : {}".format(FQDN_test_name['pcap_file']))
            with steps.start("Create access policy by enabling EVE"):
                EVE_exempt_src_host_ipv4_policy_config.advanced.eve_settings.blockThreshold = threat_score
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_host_ipv4_policy_config)
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
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
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

        elif "Exception_with_Source_Host_IPV6" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            log.info("n/w object: {}".format(FQDN_test_name['dst_object']))
            log.info("pcap file : {}".format(FQDN_test_name['pcap_file']))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_src_host_ipv6_policy_config)
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
                else:
                    # log.info("fingerprints are not generated")
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

        elif "Exception_with_Source_IPV4_range" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_range_source_ipv4_policy_config)
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
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
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

        elif "Exception_with_Source_IPv6_range" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_range_source_ipv6_policy_config)
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
                else:
                    # log.info("fingerprints are not generated")
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

        elif "Exception_with_Source_IPV4_network" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_source_network_ipv4_policy_config)
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
                commonSourceNet().pcap_replay(api_service_fmc1, endpoint1_ssh, file_path, file_name, ftd1_ssh, data_purge)
            with steps.start("Veryfying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
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

        elif "Exception_with_Source_IPv6_network" == FQDN_test_case:
            log.info("Testcase: {}".format(FQDN_test_case))
            with steps.start("Create access policy by enabling EVE"):
                ret_val = utility_eve.create_access_policy(api_service_fmc1, device,
                                                           EVE_exempt_source_network_ipv6_policy_config)
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
            with steps.start("Verifying the Fingerprints"):
                wget_ret_val = EVE_utils().wget_traffic_validations(testbed)
                if wget_ret_val:
                    log.info("fingerprints are generated")
                else:
                    # log.info("fingerprints are not generated")
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