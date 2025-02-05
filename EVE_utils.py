import re
import subprocess
import sys
import time
import logging
import traceback
import random
import paramiko
import polling
 
from lib.models.devices.device_management.device.interfaces.physical_interface.model import PhysicalInterface
from lib.models.devices.device_management.high_availability.constants import HATaskStatus, UpdateHAActions
from lib.models.devices.device_management.high_availability.model import HighAvailability
from lib.common_modules.cli_connection import get_cli_connection
from lib.constants import TestBedConstants
from lib.models.deploy.model import DeploymentRequest
from lib.models.devices.device_management.device.model import Device
from lib.models.fragments.advanced_access_policy.eve_exception_rulelist_settings.model import \ EveExceptionRuleListFragment
from lib.models.fragments.advanced_access_policy.model import AdvancedAccessPolicyFragment
from lib.models.fragments.rules.networks.model import RuleNetworksFragment
from lib.models.objects.dynamic_objects.mappings.model import DynamicObjectMapping
from lib.models.objects.dynamic_objects.model import DynamicObject
from lib.models.objects.interface.interface_group.model import InterfaceGroupObject
from lib.models.objects.interface.security_zone.model import SecurityZoneObject
from lib.models.objects.network.network_object.model import NetworkObject
from lib.models.policies.access_control.access_control.access_policy.access_rule.model import AccessRule
from lib.models.policies.access_control.access_control.access_policy.clone_access_policy.model import CloneAccessPolicy
from lib.models.policies.access_control.access_control.access_policy.model import AccessPolicy
from lib.models.policies.access_control.access_control.access_policy.policy_assignment.model import PolicyAssignment
from lib.services.api_service import APIService
from lib.services.eventing.utils import count_events
from lib.services.system.tools.export_service import ExportService
from lib.services.system.tools.export_settings import ExportSettings
from lib.services.system.tools.import_service import ImportService
from tests.shared_libraries.common_functions import CommonFunction
from lib.services.data.store import store
from lib.services.config_provider import ConfigProvider
from lib.services.eventing.constants import EventsTypes, HowMany
from lib.services.eventing.constants import ConnectionEventsFilters, IntrusionEventsFilters
from lib.services.eventing.events import Events
from unicon.eal.dialogs import Dialog
 
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
 
class EVE_utils:
 
    def create_access_policy(self, api_service_fmc: APIService, ftd: Device, access_policy_config):
        try:
            ac_policy = api_service_fmc.create(access_policy_config)
            log.info('***** Successfully created AC policy *****')
            ac_policy_assignment = PolicyAssignment()
            ###target the device to ftd ###
            ac_policy_assignment.targets = [ftd]
            ac_policy_assignment.policy = ac_policy
            api_service_fmc.create(ac_policy_assignment)
            log.info('***** Successfully assigned AC policy to the FTD *****')
            ### deploying to ftd using fmc ###
            self.deploy_all(api_service_fmc, ftd)
            return True
        except Exception as e:
            log.info("Error while Creating Access Policy - {}".format(e))
            return False
 
    def create_high_availability(self, api_service_fmc: APIService, testbed, ftd1_ssh, ftd2_ssh,
                                 ftdha_ipv4: HighAvailability, utility1):
 
        log.info('Finding the Primary Device and Secondary device in FMC')
        primary_device = api_service_fmc.find_one(Device,
                                                   condition=lambda device_obj: device_obj.name == ftd1_ssh.device_ip)
        secondary_device = api_service_fmc.find_one(Device,
                                                     condition=lambda device_obj: device_obj.name == ftd2_ssh.device_ip)
        log.info('Finding the HA LAN & Failover Link , Primary,Secondary Device for HA creation')
 
        lanfailover_interface_from_server = api_service_fmc.find_one \
            (PhysicalInterface, condition=lambda interface: interface.name == testbed.
             devices[TestBedConstants.sensor1.value].interfaces["traffic7"].name,
             container_id=primary_device.id)
 
        statefulfailover_interface_from_server = api_service_fmc. \
            find_one(PhysicalInterface, condition=lambda interface: interface.name == testbed.
                     devices[TestBedConstants.sensor1.value].interfaces["traffic7"].name,
                     container_id=primary_device.id)
 
        ftdha_ipv4.primary = primary_device
        ftdha_ipv4.secondary = secondary_device
        ftdha_ipv4.lanFailover.interfaceObject = lanfailover_interface_from_server
        ftdha_ipv4.statefulFailover.interfaceObject = statefulfailover_interface_from_server
        try:
            log.info(" in the try block")
            ftdha_deployment = api_service_fmc.create(ftdha_ipv4)
            log.info("ftdha_deployment {}", format(ftdha_deployment))
            task_status = api_service_fmc.find_one_by_record(ftdha_deployment.taskStatus)
            log.info("Task status while creating FTD-HA {}".format(task_status))
        except Exception as e:
            CommonFunction().break_ha(api_service_fmc, ftdha_ipv4, utility1)
            log.info("Error occurred while creating FTD-HA {}".format(e))
            return False
        assert task_status.status == HATaskStatus.success.value
        return True
 

    
    ###fetching details ###
    def create_multiple_rules(self, api_service_fmc: APIService, access_policy_config, EVE_test_cases_data, device,
                              file_action = None):
        accessRuleList = []
        acPolicy = api_service_fmc.find_one(AccessPolicy,
                                             condition=lambda policy: policy.name == access_policy_config.name)
        acl_rule_count = EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['acl_rule_count']
        acl_name_prefix = EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['acl_name_prefix']
 
        for count in range(0, acl_rule_count):
            acl_rule_name = '{0}_{1}'.format(acl_name_prefix, count)
            accessRule = AccessRule(action= EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['action']
            if file_action is None else EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['block_action'],
                                    name=acl_rule_name,
                                    sendEventsToFMC=EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['sendEventsToFMC'],
                                    enabled=EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['enabled'],
                                    logBegin=EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['logBegin'],
                                    logEnd= EVE_test_cases_data['Dummy_Access_Policy_Rule_Data']['logEnd']
                                    if file_action is None else "false",
                                    insertAfter=1)
            accessRuleList.append(accessRule)
        api_service_fmc.create(accessRuleList, container_id=acPolicy.identifier)
        self.deploy_all(api_service_fmc, device)
 
    def deploy_all(self, api_service_fmc, ftd):
        try:
            deployment_to_create = DeploymentRequest()
            deployment_to_create.deviceList.append(ftd)
            api_service_fmc.create(deployment_to_create)
            log.info('***** Deployment is Successful *****')
        except Exception as e:
            log.info('Deployment Failed {}'.format(e))
 
    def configure_physical_interfaces(self, testbed, api_service_fmc: APIService, device, yaml_file,
                                      security_zone_list):
        for i in range(2):
            interface = store.get("file:{}".format(yaml_file),
                                  root_object='physical_interface.physical_interface_data{}'.format(i))
            interface_alias = testbed.devices[TestBedConstants.sensor1.value].interfaces[interface.name].alias
            name = testbed.devices[TestBedConstants.sensor1.value].interfaces[interface_alias].name
  
            interface_from_device = api_service_fmc.find_one(PhysicalInterface,
                                                              condition=lambda interface: interface.name == name,
                                                              container_id=device.identifier)
            created_security_zone = api_service_fmc.create(security_zone_list[i])
            interface.id = interface_from_device.identifier
            interface.name = interface_from_device.name
            interface.securityZone = created_security_zone
            interface_from_device.enabled = True
            api_service_fmc.update(interface, container_id=device.identifier)
        self.deploy_all(api_service_fmc, device)
 
    def check_fmc_connection_events_and_fingerprint(self, fmc):
        events = Events(fmc, event_type=EventsTypes.connection.value)
        events.field_selector(field=ConnectionEventsFilters.tlsfp.value)
        events.field_selector(field=ConnectionEventsFilters.tlsfp_process_name.value)
        events.field_selector(field=ConnectionEventsFilters.tlsfp_process_confidence_score.value)
        events.field_selector(field=ConnectionEventsFilters.tlsfp_malware_confidence.value)
        events.field_selector(field=ConnectionEventsFilters.tlsfp_malware_confidence_score.value)
        events.field_selector(field=ConnectionEventsFilters.action.value)
        result = events.search()
        log.info('result search {} '.format(result))
        tlsfp_process_name_list = list(result["VALUES"])
        fmc_events_filtered_values = [sublist for sublist in tlsfp_process_name_list if all(item != '' for item in sublist)]
        print("fmc_events_filtered_values ", fmc_events_filtered_values)
        if not fmc_events_filtered_values:
            log.info("Events are not logged in FMC")
            log.info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            log.error("Fingerprints for TLS, HTTP, and QUIC has not been Generated")
            log.info("KNOWN ISSUE - Bug (https://cdetsng.cisco.com/webui/#view=CSCwi17256)")
            log.info("*** NOTE: Fingerprints are not generated in Unified FMC Events  ***")
            log.info("*** Re-Enabling the EVE will generate it which is a known ISSUE ***")
            log.info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            fmc_events_filtered_values = False
        else:
            log.info("'tlsfp, tlsfp_process_name, tlsfp_process_confidence_score, tlsfp_malware_confidence,tlsfp_malware_confidence_score, action ' are present in FMC events{0}".format(fmc_events_filtered_values))
            fmc_events_filtered_values = True
 
 
        for name in tlsfp_process_name_list:
            if "firefox browser" in name or "teamviewer":
                log.info("Process name - {}logged in events".format(name))
                process_name = True
                break
            else:
                log.info("Process name in FMC events is different or not logged. Process name logged - {}".format(tlsfp_process_name_list))
                process_name = False
 
        if process_name and fmc_events_filtered_values:
            return True
        else:
            return False
 
    def verify_fmc_conn_events(self, fmc, action):
        log.info('Verifying FMC connection Events')
        fmc_conn_events = Events(fmc, event_type=EventsTypes.connection.value). \
            search_filter(field=ConnectionEventsFilters.action.value, value=action). \
            field_selector(field=HowMany.count.value).search(force=True)
        conn_count = count_events(fmc_conn_events)
        if conn_count > 0:
            return True
        return False
 
    def check_intrusion_events(self, fmc):
        events = Events(fmc, event_type=EventsTypes.connection.value)
        events.field_selector(field=IntrusionEventsFilters.inline_result_reason.value)
        result = events.search()
        log.info('result search {} '.format(result))
        if int(result['VALUES'][0][0].replace(",",'')) > 0:
            return True
        return False
 
    def enable_debug_and_traffic_validation(self, testbed, endpoint_tag, endpoint_ssh,
                                   trace_protocol='', client_ip='', server_ip='', wget_traffic=None,
                                   live_traffic_url_list=None):
        log.info("Start system support debug and initiate traffic")
        ftd_clish = get_cli_connection(testbed, device_label="sensor1")
        time.sleep(5)
        ftd_clish.go_to('sudo_state')
        ftd_clish.sendline("echo "" > /ngfw/var/log/messages")
        ftd_clish.execute('echo \"\" > /ngfw/var/log/messages')
        time.sleep(10)
        try:
            d = Dialog([
                ['Enable firewall-engine-debug', 'sendline(y)', None, True, False],
                ['Please specify an IP protocol:', 'sendline({})'.format(trace_protocol), None, True, False],
                ['Please specify a client IP address:', 'sendline({})'.format(client_ip), None, True, False],
                ['Please specify a client port:', 'sendline()', None, True, False],
                ['Please specify a server IP address:', 'sendline({})'.format(server_ip), None, True, False],
                ['Please specify a server port:', 'sendline()', None, True, False],
                ['Monitoring application identification and firewall debug messages.*', 'sendline()', None, False, False]
            ])
 
            command = "system support application-identification-debug"
 
            ftd_clish.run_cmd_dialog(command, d, target_state='fireos_state', timeout=120)
            log.info("\n System support trace started successfully \n")
            endpoint = ConfigProvider(testbed, endpoint_tag)
            endpoint_conn = endpoint.get_ssh_connection().conn
 
            live_traffic_ret_val, wget_ret_val = True, True
            if wget_traffic is not None:
                endpoint_conn.execute(wget_traffic)
                ftd_clish.spawn_id.sendline("\x03")
                wget_ret_val = self.wget_traffic_validations(testbed)
            elif live_traffic_url_list is not None:
                live_traffic_ret_val = self.live_traffic(testbed, endpoint_tag, endpoint_ssh, live_traffic_url_list)
            else:
                log.error("No traffic specified, require either wget or live traffic URL details")
                return False
            time.sleep(10)
            ftd_clish.sendline(chr(3))
            time.sleep(5)
            if wget_ret_val and live_traffic_ret_val:
                return True
            return False
        except Exception as e:
            log.error(e)
            log.info("Unable to start System support application-identification-debug")
            return False
        finally:
            ftd_clish.disconnect()
 
    def wget_traffic_validations(self, testbed):
        ftd_shell = get_cli_connection(testbed, device_label="sensor1")
        ftd_shell.execute('\x03')
        ftd_shell.go_to('fireos_state')
        ftd_shell.execute('\x03')
        ftd_shell.go_to('sudo_state')
        res_log = ftd_shell.execute_lines('tail -1000 /ngfw/var/log/messages')
        print(f'\n\n Here are the log messages:{res_log}')
        ftd_shell.disconnect()
        if re.search('tls/1', res_log) is not None or re.search('fingerprint: http/', res_log) is not None or re.search('fingerprint: quic/', res_log) is not None:
            log.info("wget traffic validation passed. Fingerprints logged in '/ngfw/var/log/messages'")
            return True
        log.info("wget traffic validation failed. Fingerprints not logged in '/ngfw/var/log/messages'")
        return False
 
    def portscan_attacker_command(self, testbed):
        ftd_shell = get_cli_connection(testbed, device_label="sensor1")
        ftd_shell.go_to('fireos_state')
        ret_val = ftd_shell.execute("show threat-detection portscan attacker",timeout = 60)
        if ret_val != None:
            return True
        return False
 
    def protscan_shun_command(self, testbed):
        ftd_shell = get_cli_connection(testbed, device_label="sensor1")
        ftd_shell.go_to('fireos_state')
        ret_val = ftd_shell.execute("show threat-detection portscan shun", timeout = 60)
        if ret_val != None:
            return True
        return False
 
    def live_traffic(self, testbed, endpoint_tag, endpoint_ssh, live_traffic_url_list):
        shell_script = f"""
#!/bin/bash
 
if [ $# -eq 1 ]; then
    URL="$1"
else
    echo "Usage: $0 <URL>"
    echo "No URL specified"
    exit 1
fi
 
( firefox --headless --new-tab "$URL" ) &
 
sleep 60
 
sudo pkill -P $$ firefox
 
wait
 
HTTP_STATUS=$(curl -s -o /dev/null -w "200" "$URL")
 
if [ $? -eq 0 ] && [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Webpage opened successfully (HTTP Status: $HTTP_STATUS) (Web page: $URL)"
else
    echo "Failed to open webpage (HTTP Status: $HTTP_STATUS) (Web page: $URL)"
fi
        """
        endpoint_ip = str(testbed.devices[endpoint_tag].connections.management.ip)
        endpoint_user = testbed.devices[endpoint_tag].connections.management.user
        endpoint_port = testbed.devices[endpoint_tag].connections.management.port
        endpoint_passwd = testbed.devices[endpoint_tag].connections.management.password
 
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(endpoint_ip, endpoint_port, endpoint_user, endpoint_passwd)
 
        remote_script_path = "/root/url_check.sh"
        try:
            with ssh_client.open_sftp().file(remote_script_path, 'w') as f:
                f.write(shell_script)
            print(f"Script '{remote_script_path}' created on the remote machine.")
            log.info("")
            endpoint_ssh.conn.execute("chmod +x /root/url_check.sh")
            for url in live_traffic_url_list:
                log.info("Loading URL {}".format(url))
                ret_val = endpoint_ssh.conn.execute("./url_check.sh {}".format(url),timeout = 240)
                if "Webpage opened successfully" not in ret_val:
                    return False
            return True
        finally:
            endpoint_ssh.conn.execute("rm {}".format(remote_script_path),timeout = 240)
            ssh_client.close()
 
    def check_for_rule_file(self, ftd_cli, dst_object):
        ftd_cli.execute('\x03')
        ftd_cli.go_to('fireos_state')
        ftd_cli.execute('\x03')
        ftd_cli.go_to('sudo_state')
        result = ftd_cli.execute_lines(f'ls -lh /ngfw/var/sf/detection_engines/*/ | grep exempt')
        rule_result = ftd_cli.execute_lines(f'cat /ngfw/var/sf/detection_engines/*/exempt.rules')
        if dst_object in rule_result:
            log.info("Destination object is present in the rule file")
            return True
        else:
            return False
 
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
        tcpreplay_cmd = "tcpreplay --intf1=eth1 --topspeed {}/{}".format(ep_path, pcap_name)
        endpoint1_ssh.conn.execute(tcpreplay_cmd)
 
    def show_snort_counters_eve_exempted(self, ftd_shell):
        """
             This function is used to validate command show snort counters on FTD device
             :param ftd_ssh: FTD Device handle
        """
        cmd_output = ftd_shell.conn.execute('show snort counters | begin eve_handler')
        try:
            exempted = re.search('\s+total_sessions_exempted:\s+(\d+)', cmd_output)
            log.info("exempted counter : {}".format(exempted))
            if exempted:
                exempted_count = int(exempted.group(1))
                log.info("exempted_count : {}".format(exempted_count))
                if exempted_count > 0:
                    cmd_output = ftd_shell.conn.execute('clear conn')
                    return True
            else:
                return False
        except:
            log.info('{} is causing assertion error message'.format('show_snort_counters_command_output_collection'))
 
    def check_exempted_events(self, fmc):
        result = Events(fmc, event_type=EventsTypes.connection.value). \
            search_filter(field=ConnectionEventsFilters.action.value, value="Allow"). \
            search_filter(field=ConnectionEventsFilters.reason.value, value="EVE Exempted"). \
            field_selector(field=HowMany.count.value).search(force=True)
            # search_filter(field=ConnectionEventsFilters.tlsfp_malware_confidence.value, value="Very High"). \
            # search_filter(field=ConnectionEventsFilters.tlsfp_malware_confidence_score.value, value="100%"). \
            # search_filter(field=ConnectionEventsFilters.tlsfp_process_name.value, value="gnu wget"). \
            # search_filter(field=ConnectionEventsFilters.reason.value, value="EVE Exempted"). \
        log.info("search events results {}".format(result))
        how_many_events = count_events(result)
        if how_many_events == 0:
            log.info("No exempted connection registered  in fmc connection events\n")
            return False
        else:
            log.info("There are {} connection events matching exemption rule\n".format(how_many_events))
            return True
 
    ### step,  timeout -> it will repetedly loop until it become suceess or else it will wait till timeouut time if it is not success then after that timeout tmie it will give error msg ### 
    def verify_exempted_events(self,fmc):
        try:
            log.info("polling started")
            if polling.poll(lambda: self.check_exempted_events(fmc) is True, step=15, timeout=120):
                log.info("event found polling ended")
                return True
            else:
                log.info("polling time out")
                return False
        except:
            pass
            return False
 
    def check_core_file(self, ftd1_ssh):
        ftd1_ssh.conn.go_to('sudo_state')
        ftd1_ssh.conn.execute('cd /ngfw/var/data/cores')
        output = ftd1_ssh.conn.execute('ls -l | grep core')
        ftd1_ssh.conn.go_to('fireos_state')
        if 'snort3' in output:
            log.error('Found Snort3 cores')
            return 1
        else:
            log.info('No Snort3 cores found')
            return 0
 
    def switch_high_availability(self, api_service_fmc1: APIService):
        haList = api_service_fmc1.find_all(HighAvailability)
        haname = haList[0].name
        ftdha_to_switch = api_service_fmc1.find_one(HighAvailability,
                                                   condition=lambda obj: obj.name == haname)
        ftdha_to_switch.action = UpdateHAActions.switchHA.value
        api_service_fmc1.update(ftdha_to_switch)
        task_status = api_service_fmc1.find_one_by_record(ftdha_to_switch.taskStatus)
        ftdha_pair = api_service_fmc1.find_one(HighAvailability,
                                                   condition=lambda obj: obj.name == haname)
        if task_status.status == HATaskStatus.success.value:
            return True
        else:
            return False
 
    def break_high_availability(self, api_service_fmc1: APIService):
        haList = api_service_fmc1.find_all(HighAvailability)
        breakhaname = haList[0].name
        ftdha_to_break = api_service_fmc1.find_one(HighAvailability,condition=lambda obj: obj.name == breakhaname)
        ftdha_to_break.action = UpdateHAActions.breakHA.value
        ftdha_to_break._polling_max_timeout = 18000
        ftdha_to_break.forceBreak = 'true'  # for Force Break, this key is set to true
        api_service_fmc1.update(ftdha_to_break)
        log.info("break ha completed")
        polling.poll(lambda: api_service_fmc1.find_one(HighAvailability,
                            condition=lambda obj: obj.name == breakhaname) is None,
                            step=15,
                            timeout=360000
                        )
        broken_ftdha = api_service_fmc1.find_one(HighAvailability, condition=lambda obj: obj.name == breakhaname)
        if broken_ftdha is None:
            return False
        else:
            return True
 
    def pcap_replay_cluster(self, api_service_fmc1: APIService, endpoint1_ssh, pcap_path, pcap_name, ftd_shell,
                            data_purge):
        ep_path = "/root/eve_test_pcaps/"
        path = "{}/{}".format(pcap_path, pcap_name)
        print(path)
        log.info("copying pcap file from {} to device {}".format(path, ep_path))
        endpoint1_ssh.conn.execute("cd {}".format(ep_path), prompt="#|$")
        ftd_shell.conn.execute('clear snort counters')
        ftd_shell.conn.execute('clear conn')
        self.purge_selected_events(api_service_fmc1, data_purge)
        outfilename = pcap_name[0:-5] + "vtest.pcap"
        macchange_cmd = "tcprewrite --infile {}{} --outfile {}{} --enet-dmac=00:50:56:10:10:10".format(ep_path,
                                                                                                       pcap_name,
                                                                                                       ep_path,
                                                                                                       outfilename)
        print("mac change command", macchange_cmd)
        endpoint1_ssh.conn.execute(macchange_cmd, prompt="#|$")
        tcpreplay_cmd = "tcpreplay --intf1=eth1 --topspeed {}{}".format(ep_path, outfilename)
        print("tcpreplay command", tcpreplay_cmd)
        endpoint1_ssh.conn.execute(tcpreplay_cmd, prompt="$|#")
 
    def check_for_rule_content(self, ftd_cli):
        temp = ftd_cli.execute_lines('ls -lh /ngfw/var/sf/detection_engines')
        temp_dir = temp.split(' ')[-1]
        result = ftd_cli.execute_lines(f'cat /ngfw/var/sf/detection_engines/{temp_dir}/exempt.rules | grep exempt')
        return result
 
    def check_fmc_block_connection_events(self, fmc):
        events = Events(fmc, event_type=EventsTypes.connection.value).search_filter(field=ConnectionEventsFilters.action.value, value="Block")
        # events.field_selector(field=ConnectionEventsFilters.tlsfp.value)
        events.field_selector(field=ConnectionEventsFilters.tlsfp_process_name.value)
        # events.field_selector(field=ConnectionEventsFilters.tlsfp_process_confidence_score.value)
        # events.field_selector(field=ConnectionEventsFilters.tlsfp_malware_confidence.value)
        events.field_selector(field=ConnectionEventsFilters.tlsfp_malware_confidence_score.value)
        events.field_selector(field=ConnectionEventsFilters.action.value)
        result = events.search()
        log.info('result search {} '.format(result))
        tlsfp_process_name_list = list(result["VALUES"])
        print("tlsfp_process_name_list ", tlsfp_process_name_list)
        # Filter processes starting with 'malware'
        malware_processes = [process for process in tlsfp_process_name_list if process[1].startswith('malware')]
        # Find the maximum count malware connection
        if malware_processes:
            max_count = max(int(process[0]) for process in malware_processes)
            # Filter the list to get the process(es) with the maximum percentage
            malware_process_with_max_percentage = [(process[1], process[2]) for process in malware_processes if
                                                int(process[0]) == max_count]
            for process_info in malware_process_with_max_percentage:
                print("Process:", process_info[0])
                print("Percentage:", process_info[1])
            return malware_process_with_max_percentage
            # return process_info[0], process_info[1]
        else:
            return None
 
    def get_exempted_count_live_traffic(self,ftd_ssh):
        cmd_output = ftd_ssh.conn.execute('show snort counters module eve')
        try:
            exempted = re.search('\s+total_sessions_exempted:\s+(\d+)', cmd_output)
            if exempted:
                count = int(exempted.group(1))
                ftd_ssh.conn.execute('clear conn')
                ftd_ssh.conn.execute('clear snort counters')
                ftd_ssh.conn.execute('clear snort counters')
                return count
            else:
                log.info('Exempted issue')
                return False
        except:
            log.info('{} is causing assertion error message'.format('show_snort_counters_command_output_collection'))
            return False
 
    def dns_host_check(self,ftd1_ssh, hostname, ip_addr):
        res=ftd1_ssh.conn.execute("show dns host {}".format(hostname))
        if ip_addr in res:
            return True
        else:
            return False
            
    def clone_access_policy(self, api_service_fmc: APIService, ftd: Device, access_policy_config):
        try:
            cloning_acp = api_service_fmc.find_one(AccessPolicy,
                                                   lambda obj: obj.name == access_policy_config.name)
            cloning_acp.cloneName = cloning_acp.name + '-copy'
            cloned_policy = CloneAccessPolicy(policies=[cloning_acp])
            api_service_fmc.create(cloned_policy)
            log.info('***** Successfully cloned AC policy *****')
            return True
 
        except Exception as e:
            log.info("Error while Cloning Access Policy - {}".format(e))
            return False
 
    def export_access_policy(self, api_service_fmc1, ac_policy_name):
        try:
            ac_policy_to_export = api_service_fmc1.find_one(AccessPolicy,
                                                            lambda obj: obj.name == ac_policy_name)
            assert ac_policy_to_export is not None, "AC Policy to be exported {} doesn't exist on FMC!".format(
                ac_policy_name)
            sfo_path = "/tmp/"
            log.info("SFO path : " + sfo_path)
            export_serv = ExportService(api_service_fmc1.context)
            export_settings = ExportSettings()
            export_settings.export_access_control_policy_list([ac_policy_name])
            export_serv.export_objects = export_settings
            export_serv.export_to_file(sfo_path + "ExportFile" + '.sfo')
            return True
        except Exception as e:
            log.info("Export configuration failed due to e={} {} {}".format(e, traceback.format_exc(), sys.exc_info()))
            return False
 
    def try_import(self, import_path, import_service):
        SEZ_regex = "ERROR:\s+\'([a-zA-Z0-9_-]+)\'\s+(.*)\s+Object\s+with\s+\'([a-zA-Z0-9_-]+)\'\s+type\s+doesn't\s+exist\.\s+interface\s+group\s+\-\>\s+(\d)"
        import_error_regex = "ERROR:\s+Failed while importing: Software version mismatch"
        try:
            import_service.import_file(import_path, timeout=1800)
        except Exception as err:
            import_err_match = re.search(import_error_regex, err.args[0])
            if import_err_match:
                return False, 0, None, None, None, None
            required_match = re.search(SEZ_regex, err.args[0])
            if required_match:
                return False, 1, required_match.group(1), required_match.group(2), required_match.group(3), \
                    required_match.group(4)
            else:
                log.info('Import failed !!! Since user trying to load Invalid .sfo -> {}'.format(import_path))
                return False, 0, None, None, None, None
        return True, 1, None, None, None, None
    #re-use
    def import_access_policy_sfo(self, api_service_fmc1: APIService, sfo_path):
        import_serv = ImportService(api_service_fmc1.context)
        log.info('local sfo path: {}'.format(sfo_path))
        result = False
        while not result:
            result, version, object_name, object_type, object_mode, zone_type = self.try_import(sfo_path, import_serv)
            if not version:
                log.info('trying to load {} into Incorrect FMC version!!!'.format(sfo_path))
                return False
            if not result:
                if int(zone_type):
                    api_service_fmc1.create(InterfaceGroupObject(name=object_name, interfaceMode=object_mode.upper()))
                else:
                    api_service_fmc1.create(SecurityZoneObject(name=object_name, interfaceMode=object_mode.upper()))
            else:
                log.info('{}  loaded successfully!!!'.format(sfo_path))
                return True
 
    def assign_random_network_objects(self, network_object_name, count):
        fqdn_dynamic_object = NetworkObject(
            name="fqdn_" + network_object_name,
            type="FQDN",
            dnsResolution="IPV4_ONLY",
            value="test-{0}.eve.com".format(count),
            overridable=False,
            description="Created automatically from REST API"
        )
        host_network_value = NetworkObject(
            name="host" + network_object_name,
            type="Host",
            value="172.16.3.4",
            overridable=False,
            description="Created automatically from REST API"
        )
        range_dynamic_object = NetworkObject(
            name="range_" + network_object_name,
            type="Range",
            value="172.16.2.1-172.16.2.5",
            overridable=False,
            description="Created automatically from REST API"
        )
        network_dynamic_object = NetworkObject(
            name="network_" + network_object_name,
            type="Network",
            value="172.16.2.0/24",
            overridable=False,
            description="Created automatically from REST API"
        )
 
        network_objects = [fqdn_dynamic_object, range_dynamic_object, network_dynamic_object, host_network_value]
        return random.choice(network_objects)
 
    def create_multiple_exception_rules(self, api_service_fmc: APIService, access_policy_config, EVE_test_cases_data,
                                        device):
        try:
            ExceptionRuleList = []
            acPolicy = api_service_fmc.find_one(AccessPolicy,
                                                condition=lambda policy: policy.name == access_policy_config.name)
            advanced_fragment = api_service_fmc.find_one_by_record(AdvancedAccessPolicyFragment(),
                                                                   container_id=acPolicy.id)
            # rule count
            exception_rule_count = EVE_test_cases_data['EVE_exception_Rule_Data']['exception_rule_count']
            network_object_name_prefix = EVE_test_cases_data['dest_fqdn_host_object']['name_prefix']
            dynamic_object_name_prefix = EVE_test_cases_data['dynamic_host_object']['name_prefix']
            process_name_list = EVE_test_cases_data['EVE_exception_Rule_Data']['process_name_prefix']
            i = 7
            log.info("***********************************************************************************************")
            for count in range(0, exception_rule_count):
                if count < 14:
                    process_name = process_name_list[count]
                else:
                    process_name = '{0}_{1}'.format("eve_process_name", count)
                network_object_name = '{0}_{1}'.format(network_object_name_prefix, count)
                dynamic_object_name = '{0}_{1}'.format(dynamic_object_name_prefix, count)
 
                network_object = self.assign_random_network_objects(network_object_name, count)
                destination_network = RuleNetworksFragment(
                    objects=[network_object]
                )
                dynamic_object = DynamicObject(
                    name=dynamic_object_name,
                    description=EVE_test_cases_data['dynamic_host_object']['description'],
                    objectType=EVE_test_cases_data['dynamic_host_object']['objectType'],
                    _mappings=[DynamicObjectMapping(action='add', mappings=['172.16.2.2'])]
                )
                exceptionRule = EveExceptionRuleListFragment(
                    processNameList=[process_name],
                    destinationNetwork=destination_network,
                    comments=EVE_test_cases_data['EVE_exception_Rule_Data']['comments'],
                    dynamicAttributes=dynamic_object
                )
                if i == 7:
                    log.info("Created Exception rule with all the possibilities")
                elif i == 6:
                    exceptionRule.dynamicAttributes = None
                    exceptionRule.destinationNetwork = None
                elif i == 5:
                    exceptionRule.processNameList = None
                    exceptionRule.destinationNetwork = None
                elif i == 4:
                    exceptionRule.processNameList = None
                    exceptionRule.dynamicAttributes = None
                elif i == 3:
                    exceptionRule.dynamicAttributes = None
                elif i == 2:
                    exceptionRule.destinationNetwork = None
                elif i == 1:
                    exceptionRule.processNameList = None
                    i = 8
 
                ExceptionRuleList.append(exceptionRule)
                i -= 1
 
            api_service_fmc.create(ExceptionRuleList)
            advanced_fragment.eve_settings.eveExceptionRuleList.extend(ExceptionRuleList)
            log.info(len(advanced_fragment.eve_settings.eveExceptionRuleList))
            api_service_fmc.update(advanced_fragment.eve_settings, container_id=acPolicy.id)
            self.deploy_all(api_service_fmc, device)
            return True
        except Exception as e:
            log.info("Bulk exception rule creation failed due to e={} {} {}".format(e, traceback.format_exc(),
                                                                                    sys.exc_info()))
            return False
 
 
    def update_acPolicy_with_exception_rule(self, api_service_fmc: APIService, access_policy_config, eve_rule_config,
                                            device):
        try:
            acPolicy = api_service_fmc.find_one(AccessPolicy,
                                                condition=lambda policy: policy.name == access_policy_config.name)
            advanced_fragment = api_service_fmc.find_one_by_record(AdvancedAccessPolicyFragment(),
                                                                   container_id=acPolicy.id)
            exceptionRule = api_service_fmc.create(eve_rule_config)
            advanced_fragment.eve_settings.eveExceptionRuleList.append(exceptionRule)
            api_service_fmc.update(advanced_fragment.eve_settings, container_id=acPolicy.id)
            self.deploy_all(api_service_fmc, device)
            return True
        except Exception as e:
            log.info("Valid exception rule failed due to e={} {} {}".format(e, traceback.format_exc(), sys.exc_info()))
            return False
    def get_block_events(self, fmc):
        log.info("polling started")
        process_name = ''
        threat_score = ''
        malware_process_with_max_percentage = self.check_fmc_block_connection_events(fmc)
                if polling.poll(lambda: malware_process_with_max_percentage is not None, step=15, timeout=120):
                log.info("event found polling ended")
            for process_info in malware_process_with_max_percentage:
                print("Process:", process_info[0])
                print("Percentage:", process_info[1])
                process_name = process_info[0]
                threat_score = process_info[1]
            return process_name, threat_score
        else:
            log.info("polling time out")
            return None
        # malware_process_with_max_percentage = self.check_fmc_block_connection_events(fmc)
        # for process_info in malware_process_with_max_percentage:
        #     print("Process:", process_info[0])
        #     print("Percentage:", process_info[1])
        #     process_name = process_info[0]
        #     threat_score = process_info[1]
        # # process_name, threat_score = self.check_exempted_events(fmc)
        # if polling.poll(process_name != '' and threat_score != '', step=15, timeout=600):
        #     log.info("event found polling ended")
        #     return process_name, threat_score
        # else:
        #     log.info("polling time out")
        #     return None


    def Aquila_replay(self,ftd1_ssh,endpoint1_ssh,endpoint2_ssh,api_service_fmc1, data_purge,base_dir, pcap_path,pcapfile,client_ip_address,server_ip_address,interface):
        ep_path = "/root/eve_pcap"
        file_name = pcapfile
        file_path = "{}/{}".format(base_dir, pcap_path)
        path = "{}/{}".format(file_path, file_name)
        log.info("copying pcap file from {} to device {}".format(path, ep_path))
        endpoint1_ssh.conn.execute("mkdir -p {}".format(ep_path))
        endpoint1_ssh.copy_from_container_to_device(path, ep_path)
        time.sleep(5)
        endpoint2_ssh.conn.execute("mkdir -p {}".format(ep_path))
        endpoint2_ssh.copy_from_container_to_device(path, ep_path)
        # ftd1_ssh.conn.go_to('fireos_state')
        ftd1_ssh.conn.execute('clear snort counters')
        ftd1_ssh.conn.execute('clear conn')
        self.purge_selected_events(api_service_fmc1, data_purge)

        endpoint1_aquila_command = "/root/aquila/jdk1.8.0_65/bin/java -Djava.library.path=./libs/ -jar AquilaReplay.jar inject client {} {} /root/eve_pcap/mitreblockpcap.pcap".format(interface,client_ip_address)
        endpoint2_aquila_command = "/root/aquila/jdk1.8.0_65/bin/java -Djava.library.path=./libs/ -jar AquilaReplay.jar inject -s {} {} /root/eve_pcap/mitreblockpcap.pcap".format(interface,server_ip_address)

        log.info(endpoint2_aquila_command)
        log.info(endpoint1_aquila_command)

        endpoint2_ssh.conn.execute("cd /root/aquila/aquila_replay2/AquilaReplay")
        endpoint2_ssh.conn.execute(endpoint2_aquila_command)

        endpoint1_ssh.conn.execute("cd /root/aquila/aquila_replay2/AquilaReplay")
        endpoint1_ssh.conn.execute(endpoint1_aquila_command)
        ftd1_ssh.conn.execute('clear conn')

    def mercury_module_debug(self, ftd1_ssh):
        try:
            ftd1_ssh.conn.execute("debug packet-condition match tcp any any")
            ftd1_ssh.conn.execute("debug packet-module mercury 7")
            ftd1_ssh.conn.execute("show packet-config")
            ftd1_ssh.conn.execute("debug packet-start")
            return True
        except Exception as e:
            return False

    def eve_handler_module_debug(self, ftd1_ssh):
        try:
            ftd1_ssh.conn.execute("debug packet-condition match tcp any any")
            ftd1_ssh.conn.execute("debug packet-module eve-handler 7")
            ftd1_ssh.conn.execute("show packet-config")
            ftd1_ssh.conn.execute("debug packet-start")
            return True
        except Exception as e:
            return False

    def dual_pcap_replay(self,api_service_fmc1,data_purge,endpoint1_ssh,ftd1_ssh,pcap_file1,pcap_file2,file_path1,file_path2):
        ep_path = "/root/eve_pcap"
        endpoint1_ssh.conn.execute("mkdir -p {}".format(ep_path))
        log.info("Copying First pcap file")
        path1 = "{}/{}".format(file_path1, pcap_file1)
        log.info("copying pcap file from {} to device {}".format(path1, ep_path))
        endpoint1_ssh.copy_from_container_to_device(path1, ep_path)

        log.info("Copying Second pcap file")
        path2 = "{}/{}".format(file_path2, pcap_file2)
        log.info("copying pcap file from {} to device {}".format(path2, ep_path))
        endpoint1_ssh.copy_from_container_to_device(path2, ep_path)

        self.purge_selected_events(api_service_fmc1, data_purge)
        ftd1_ssh.conn.execute('clear snort counters')
        ftd1_ssh.conn.execute('clear conn')
        tcpreplay_cmd = "tcpreplay --intf1=eth1 --topspeed {}/{}".format(ep_path, pcap_file1)
        endpoint1_ssh.conn.execute(tcpreplay_cmd)
        time.sleep(3)
        tcpreplay_cmd2 = "tcpreplay --intf1=eth1 --topspeed {}/{}".format(ep_path, pcap_file2)
        endpoint1_ssh.conn.execute(tcpreplay_cmd2)
        endpoint1_ssh.conn.execute("rm -rf {}".format(ep_path))



        