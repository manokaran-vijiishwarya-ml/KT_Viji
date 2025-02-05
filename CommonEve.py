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
                      ConnectionEventsFilters.reason,
                      ConnectionEventsFilters.url
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