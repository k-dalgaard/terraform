import pexpect
from pexpect import pxssh
import sys
import datetime
import time
#from scp import SCPClient
import io
#from .core import Logable
import re
import telnetlib
from ntc_templates.parse import parse_output
import base64
import netmiko
import logging
from pprint import pprint

kda_login = ''


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    #filemode='w',
    handlers=[
            logging.FileHandler("script.log"),
            logging.StreamHandler()
        ]
    )
logger=logging.getLogger()



class Cli():

    loggername = 'IOS-CLI'
    COMMAND_TIMEOUT = 10
    ENCODING = 'UTF-8'

    def __init__(self, authority=None, username=None, password=None, parentwrapper=None, enable_password=None, protocol='auto', pwd_encoding=None, **kwargs):
        self.authority = authority
        self.username = username
        self.parentwrapper = parentwrapper
        self.protocol = protocol
        self.loggedin = False
        self.session = None
        self.enable_mode = False
        self.connect_timeout = 10
        self.enable_password = enable_password

        if pwd_encoding:
            if pwd_encoding == "base64":
                self.password = str(base64.b64decode(password), 'utf-8')
                if enable_password:
                    self.enable_password = str(base64.b64decode(enable_password), 'utf-8')

        else:
            self.password = password
            self.enable_password = enable_password



    def login(self, **kwargs):
        if self.protocol == 'ssh':
            self._connect_ssh(**kwargs)
            #print('status: ', status)
        elif self.protocol == 'telnet':
            self._connect_telnet(**kwargs)
        else:
            # Try SSH first, then fallback to Telnet
            logger.info('No protocol configured, trying with SSH first...')
            self._connect_ssh(**kwargs)
            if self.loggedin:
                return True

            logger.info('No session established with SSH, trying with TELNET...')
            self._connect_telnet(**kwargs)
            if self.loggedin:
                return True

            logger.error('Could not establish session to {}'.format(self.authority))
            return False

    def logout(self):
        logger.info("Closing session with {}".format(self.authority))
        self.session.disconnect()
        self.loggedin = False
        return


    def _connect_ssh(self, **kwargs):
        logger.info("Etablishing SSH session to: {}".format(self.authority))
        try:
            self.session = netmiko.Netmiko(self.authority, username=self.username, password=self.password, secret=self.enable_password, device_type='cisco_ios', **kwargs)
            if self.session:
                logger.info('Connected...')
                self.loggedin = True
                #kda_login = True
                #print('kda_ok: ', kda_login)

        except Exception as e:
            logger.error('Error establishing SSH session to: {authority}... {errmsg}'.format(authority=self.authority, errmsg=e))
            self.loggedin = False
            #kda_login = False
            #print('kda_failed: ', kda_login)

        return self.loggedin

    def _connect_telnet(self, **kwargs):
        logger.info("Etablishing TELNET session to: {}".format(self.authority))
        try:
            self.session = netmiko.Netmiko(self.authority, username=self.username, password=self.password, secret=self.enable_password, device_type='cisco_ios_telnet', **kwargs)
            if self.session:
                logger.info('Connected...')
                self.loggedin = True

        except Exception as e:
            logger.error('Error establishing TELNET session to: {authority}... {errmsg}'.format(authority=self.authority, errmsg=e))

        return self.loggedin

    def _check_init(self, skip_login_check=False, **kwargs):
        if not skip_login_check and not self.loggedin:
            logger.info('Not logged in...')
            self.login(**kwargs)
        else:
            return True


    def command(self, command,  trace=False, **kwargs):
        logger.info("Executing command ({device}): '{cmd}'".format(cmd=command,device=self.authority))
        self._check_init(**kwargs)
        try:
            result = self.session.send_command(command)
            return result
        except:
            logger.error("Error executing command ({device}): '{cmd}'".format(cmd=command,device=self.authority))
            return None

    def send_config(self, command,  trace=False, **kwargs):
        logger.info("sending command ({device}): '{cmd}'".format(cmd=command,device=self.authority))
        self._check_init(**kwargs)
        try:
            result = self.session.send_config_set(command)
            return result
        except:
            logger.error("Error executing command ({device}): '{cmd}'".format(cmd=command,device=self.authority))
            return None


class Wrapper():

    loggername = 'IOS'

    def __init__(self, **kwargs):
        self.cli = Cli(parentwrapper=self, **kwargs)

    def login(self, **kwargs):
        #print('kda_login')
        self.cli.login(**kwargs)
        #print('loggedind: ', self.cli.loggedin)
        #print('login_status: ', status)
        return self.cli.loggedin
        
        

    def logout(self, **kwargs):
        self.cli.logout(**kwargs)

    def get_running_config(self,**kwargs):
        return self.cli.command('show running-config', **kwargs)

    def get_interface_status(self, interface=None, cmd=None,  **kwargs):
        """
        Data model:
        {
        'description'   : Inteface description,
        'duplex'        : Duplex mode,
        'interface'     : Interface name,
        'speed'         : Speed,
        'status'        : Interface status,
        'type'          : Interface type,
        'vlan'          : Access VLAN / Trunk,
        }
        """
        
        if interface:
            cmd  = 'show interfaces ' + interface
        elif cmd !=None:
            cmd  =  'show interface status | i Vlan'
        else:
            cmd  = 'show interfaces status'
        #hprint(cmd)
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(raw_cli)
        #print(type(raw_cli))
        #exit()

        #cmd  = 'show interfaces status'
        try:
            result=[]
            parsed_result = parse_output(platform="cisco_ios", command=cmd, data=raw_cli)
            #print('#### get_interface_status ####')
            #print(parsed_result)

            if interface:
                if parsed_result == []:
                    data = {
                        'link_status'      : 'None',
                        'protocol_status'  : 'None'
                    }
                    result.append(data)
                else:
                    for intf in parsed_result:
                        data = {
                            'interface'        : intf['interface'],
                            'link_status'      : intf['link_status'],
                            'protocol_status'  : intf['protocol_status']
                        }
                        result.append(data)
                        #print(result)
            else:
               # print('ELSE')
                
                for item in parsed_result:
                    item['description'] = item['name']
                    item['interface'] = item['port']
                    del item['name']
                    del item['port']
                    result.append(item)
                
            return result
        except Exception as e:
            logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            logger.debug('Exception thrown: {}'.format(e))
            return None

    def get_mac_address_table(self, interface=None, vlan=None, exclude_CPU=False, **kwargs):

        if interface:
            cmd = 'show mac address-table interface ' + interface
        else:
            cmd = 'show mac address-table'

        #print(cmd)
         #cmd = "sh vlan"
         #cmd = "show interface g0/2"
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(raw_cli)
        try:
            result = []
            parsed_result = parse_output(platform="cisco_ios", command=cmd, data=raw_cli)
            if interface:
                if parsed_result == []:
                    data = {
                        'mac_address' : 'None',
                        }
                    result.append(data)
                    return result
                else:
                    for mac in parsed_result:
                        data = {
                            'mac_address' : mac['destination_address'],
                            'vlan'        : mac['vlan']
                            }
                        result.append(data)
                        #print(result)
                    return result



            return parsed_result

        except Exception as e:
            #logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            logger.debug('Exception thrown: {}'.format(e))
            return None

    def get_cdp_neighbors(self, interface=None, detail=None, **kwargs):
        cmd = 'show cdp neighbors'
        cmd1 = 'show cdp neighbors'
        #print('skip_login_check: ', skip_login_check)
        if interface:
            cmd1 = cmd1+" {}".format(interface)
        if detail:
            cmd = cmd+" detail"
            cmd1 = cmd1+" detail"

        raw_cli = self.cli.command(cmd1, **kwargs)

        try:
            result = parse_output(platform="cisco_ios", command=cmd, data=raw_cli)
            return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None


    def show_auth_session(self, **kwargs):
        cmd = 'show authentication sessions'
        template = 'show authentication session'
        raw_cli = self.cli.command(cmd, **kwargs)
#        print(raw_cli)
        try:
             result = parse_output(platform="cisco_ios", command=template, data=raw_cli)
             #print(result)
             return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None



    def show_auth_session_detail(self, cmd=None, **kwargs):
        #cmd = 'show authentication sessions interface g3/0/2 details'
        template = 'show authentication sessions details'
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_ios", command=template, data=raw_cli)
             #print(result)
             return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None
    
    def show_crypto_pki_certificates(self, cmd=None, **kwargs):
        #cmd = 'show authentication sessions interface g3/0/2 details'
        template = 'show crypto pki certificates'
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_ios", command=template, data=raw_cli)
             #print(result)
             return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None


    def show_mac_address_table(self, cmd=None,**kwargs):
        #cmd = 'show mac address-table'
        template = 'show mac address-table'
        raw_cli = self.cli.command(cmd, **kwargs)
        #print("ios.py: ", cmd )
        print("\n\nios.py - def: show_mac_addresser_table: ", cmd , "\n\n" )
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_ios", command=template, data=raw_cli)
             #print(result)
             return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None

    def nxos_show_mac_address_table(self, cmd=None,**kwargs):
        #cmd = 'show mac address-table'
        template = 'show mac address-table'
        raw_cli = self.cli.command(cmd, **kwargs)
        print("\n\nios.py - def: nxos_show_mac_addresser_table: ", cmd , "\n\n" )
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_nxos", command=template, data=raw_cli)
             #print(result)
             return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None

    def show_version(self, **kwargs):
        cmd = 'show version'
        template = 'show version'
        raw_cli = self.cli.command(cmd, **kwargs)
        try:
             result = parse_output(platform="cisco_ios", command=template, data=raw_cli)
            # print(result)
             return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None

    def traceroute(self, cmd=None, **kwargs):
        #cmd = 'show authentication sessions interface g3/0/2 details'
        template = 'traceroute'
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_ios", command=template, data=raw_cli)
             #print(result)
             return result
        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None        


    def nxos_show_vlan(self, cmd,  **kwargs):
        template = 'show vlan'
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(type(raw_cli))
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_nxos", command=template, data=raw_cli)
             #print(result)
             return result

        except Exception as e:
            self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            self.logger.debug('Exception thrown: {}'.format(e))
            return None

    def nxos_show_run_interface(self, cmd,  **kwargs):
        template = 'show running interface'
        cmd = 'show running interface all'
        #cmd = 'show run interface Eth2/26.999'
        #raw_cli = (
        #    "interface Vlan101"
        #)
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_nxos", command=template, data=raw_cli)
             #print(result)
             #quit()
             return result

        except Exception as e:
            print(("Error parsing command ({device}): '{cmd}'".format(cmd=cmd,device=self.cli.authority)))
            #self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            #self.logger.debug('Exception thrown: {}'.format(e))
            return None       


    def nxos_show_ip_route(self, cmd,  **kwargs):
        template = 'show ip route'
        #cmd = 'show running interface all'
        #cmd = 'show run interface Eth2/26.999'
        #raw_cli = (
        #    "interface Vlan101"
        #)
        raw_cli = self.cli.command(cmd, **kwargs)
        #print(raw_cli)
        try:
             result = parse_output(platform="cisco_nxos", command=template, data=raw_cli)
             #print(result)
             #quit()
             return result

        except Exception as e:
            print(("Error parsing command ({device}): '{cmd}'".format(cmd=cmd,device=self.cli.authority)))
            #self.logger.error("Error parsing command ({device}): '{cmd}'".format(cmd=command,device=self.cli.authority))
            #self.logger.debug('Exception thrown: {}'.format(e))
            return None       

    def exec_send_config(self, command,  **kwargs):
        raw_cli = self.cli.send_config(command,  **kwargs)
        return raw_cli

    def exec_command(self, command,  **kwargs):
        #print(command)
        raw_cli = self.cli.command(command,  **kwargs)
        #print(raw_cli)



        return raw_cli
