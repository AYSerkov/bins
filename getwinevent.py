# Author:
#   Alberto Riocool (t.me/riocool)


from __future__ import division
from __future__ import print_function
import argparse
import sys
import logging
from threading import Timer, current_thread

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY


class Reply():
    def __init__(self):
        self.reply = ''

    def add(self, data):
        self.reply += data

    def newline(self):
        self.reply += '\n'

    def print(self):
        print(self.reply)

    def raw_data(self):
        return self.reply

    def save_to_file(self, filename):
        f = open(filename, 'w')
        f.write(self.reply)
        f.close()

class DCOM():
    def __init__(self, domain, username, password, address, namespace='//./root/cimv2', timeout=3000, rpc_auth_level='default',
                 hashes=None, no_pass=None, aesKey=None, k=None, dc_ip=None):
        self.domain, self.username, self.password, self.address = domain, username, password, address
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')
        else:
            self.lmhash = ''
            self.nthash = ''
        if self.domain is None:
            self.domain = ''
        if self.password == '' and self.username != '' and hashes is None and no_pass \
                is False and aesKey is None:
            from getpass import getpass
            self.password = getpass("Password:")
        try:
            self.dcom = DCOMConnection(self.address, self.username, self.password, self.domain,
                                       self.lmhash, self.nthash, aesKey, oxidResolver=True,
                                       doKerberos=k, kdcHost=dc_ip)

            self.iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            self.iWbemLevel1Login = wmi.IWbemLevel1Login(self.iInterface)
            self.iWbemServices = self.iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            # Set more timeout
            __oxid = list(self.iInterface.CONNECTIONS[self.address]['MainThread'].keys())[0]
            self.iInterface.CONNECTIONS[self.address]['MainThread'][__oxid]['dce']._transport._TCPTransport__socket.settimeout(int(timeout))
            if rpc_auth_level == 'privacy':
                self.iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            elif rpc_auth_level == 'integrity':
                self.iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

            self.iWbemLevel1Login.RemRelease()
        except Exception as e:
            logging.error(str(e))
            try:
                self.dcom.disconnect()
            except:
                pass
    @staticmethod
    def buid_reply(record):
        reply = ''
        for key in record:
            if type(record[key]['value']) is list:
                for item in record[key]['value']:
                    reply+=f'{item} '
                reply+=' | '
            else:
                reply+=f"{record[key]['value']} | "
        reply += '\n'
        return reply

    def RemRelease(self):
        try:
            self.iWbemServices.RemRelease()
        except:
            logging.error("DCOM object not created. You can't call RemRelease")

    def disconnect(self):
        try:
            self.dcom.disconnect()
        except:
            logging.error("DCOM object not created. You can't call disconnect")

    def returnReply(self, iEnum, reply, filter=None):
        printHeader = True
        while True:
            try:
                pEnum = iEnum.Next(0xffffffff, 1)[0]
                record = pEnum.getProperties()
                if printHeader is True:
                    reply.add('| ')
                    for col in record:
                        reply.add(f'{col} | ')
                    reply.newline()
                    printHeader = False
                if filter:
                    if '!' in filter[0]:
                        if not filter.lower()[1:] in record['Message']['value'].lower():
                            reply.add(DCOM.buid_reply(record))
                    elif filter.lower() in record['Message']['value'].lower():
                        reply.add(DCOM.buid_reply(record))
                else:
                    reply.add(DCOM.buid_reply(record))
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break
        iEnum.RemRelease()
        return reply

    def query(self, line, filter=None):
        line = line.strip('\n')
        reply = Reply()
        if line[-1:] == ';':
            line = line[:-1]
        try:
            iEnumWbemClassObject = self.iWbemServices.ExecQuery(line.strip('\n'))
            self.returnReply(iEnumWbemClassObject, reply, filter)
            iEnumWbemClassObject.RemRelease()
            return reply
        except Exception as e:
            logging.error(str(e))


if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Executes WQL queries and gets object descriptions "
                                                                "using Windows Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-namespace', action='store', default='//./root/cimv2',
                        help='namespace name (default //./root/cimv2)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION", help='DCOM version, '
                                                                                                    'format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-rpc-auth-level', choices=['integrity', 'privacy', 'default'], nargs='?', default='default',
                       help='default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy '
                            '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require '
                            'privacy level by default)')
    parser.add_argument('-outputfile', action='store', metavar="FileName",
                        help='Base output filename')
    parser.add_argument('-timeout', action='store',
                       default='3000',
                       help='Timeout of tcp connection. Default 3000')
    parser.add_argument('-journal', choices=['Application', 'Security', 'Setup', 'System'], action='store',
                       default='Security',
                       help='Choose event log journal: Application, Security, Setup, System. Default Security')
    parser.add_argument('-event-id', action='store', metavar='Event ID', default='4624',
                       help='Event ID. Default Logon event')
    parser.add_argument('-grep', action='store', help='Filter event message for substring. For example, username. '
                                                      'If you want negative grep use \'!\'. Example: -grep \'!$\'')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    if options.aesKey is not None:
        options.k = True

    domain, username, password, address = parse_target(options.target)
    dcom = DCOM(domain=domain, username=username, password=password, address=address,
                namespace=options.namespace, timeout=int(options.timeout), rpc_auth_level=options.rpc_auth_level,
                hashes=options.hashes, no_pass=options.no_pass, aesKey=options.aesKey, k=options.k, dc_ip=options.dc_ip)
    reply = dcom.query(f"SELECT * FROM Win32_NTLogEvent WHERE Logfile='{options.journal}' AND EventCode='{options.event_id}'",
                       options.grep)
    reply.print()
    dcom.RemRelease()
    dcom.disconnect()
