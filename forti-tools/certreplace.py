#! /usr/bin/python

"""Import a cert file to a Fortigate."""
import os
import sys


def ensure_interpreter():
    """Ensure we are running under the correct interpreter and environ."""
    abs_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.normpath(os.path.join(abs_dir, '../'))
    desired_interpreter = os.path.join(project_root, 'bin/python')
    if os.path.abspath(sys.executable) == desired_interpreter:
        return
    env = dict(os.environ)

    def prefix_paths(key, prefix_paths):
        """Add prefix paths, relative to the project root."""
        new_paths = [os.path.join(project_root, p) for p in prefix_paths]
        new_paths.extend(env.get(key, '').split(':'))
        env[key] = ':'.join(new_paths)
    prefix_paths('PYTHONPATH', ['dir1', 'dir2'])
    prefix_paths('LD_LIBRARY_PATH', ['lib'])
    prefix_paths('PYTHON_EGG_CACHE', ['var/.python-eggs'])
    env['PROJECT_ROOT'] = project_root
    os.execvpe(desired_interpreter, [desired_interpreter] + sys.argv, env)


ensure_interpreter()


from fortiosapi import FortiOSAPI
import argparse
import configparser
from getpass import getpass


def __getConfSection__(config, section):
    try:
        return config[section]
    except Exception:
        return None


def __getArg__(config, cli, arg, arg_default=None):
    if cli:
        return cli
    try:
        return config[arg]
    except Exception:
        return arg_default


def findcert(fortiapi, certname, verbose=False):
    """Find the latest certificate with certname in FortiOS."""
    newest = None
    newestcert = None
    certificates = fortiapi.get('certificate', 'local')['results']
    if verbose:
        print('Looking for certificates.')
    for certificate in certificates:
        if certname in certificate['name']:
            if (not newest) or (certificate['last-updated'] > newest):
                newest = certificate['last-updated']
                newestcert = certificate['name']
                if verbose:
                    print('Changing to {0} as the newest certificate'.format(newestcert))
    if verbose:
        print('Choosing certificate {0}'.format(newestcert))
    return newestcert


def find_vips(fortiapi, oldcertname, viptype, vdom='root', verbose=False):
    """Find all vips with oldcertname and returns them as a list."""
    vipnames = []
    vips = fortiapi.get('firewall', viptype, vdom=vdom)['results']
    for vip in vips:
        if oldcertname in vip['ssl-certificate']:
            if verbose:
                print('Choosing {0} with certificate name {1}'.format(vip['name'], vip['ssl-certificate']))
            vipnames.append(vip['name'])
            if verbose:
                print('adding {vipname} to list of vipnames'.format(vipname=vip['name']))
    return vipnames


def changecert(
    fortiapi,
    certname,
    oldcertname=None,
    vip=False,
    vip6=False,
    sslvpn=False,
    adminui=False,
    userauth=False,
    vipname=None,
    scope='global',
    vdom='root',
    verbose=False
):
    """Change the certificates in FortiOS."""
#    Initialize variable needed for CA import.
    path = None
    name = None
    resource = None
    certname = findcert(fortiapi, certname, verbose=verbose)
    response = None
    if vip:
        path = 'firewall'
        name = 'vip'
        resource = 'ssl-certificate'
        vipnames = []
        data = {resource: certname}
        if (not vipname) and oldcertname:
            if verbose:
                print('Finding vips with {0} in the certname'.format(oldcertname))
                print(oldcertname, name, vdom)
            vipnames = find_vips(fortiapi, oldcertname, name, vdom=vdom, verbose=verbose)
        if vipname:
            vipnames.append(vipname)
            if verbose:
                print("adding {vipname} to vipnames".format(vipname))
        if vipnames:
            for item in vipnames:
                response = fortiapi.put(path, name, mkey=item, vdom=vdom, data=data)
                if verbose:
                    print(
                        path,
                        name,
                        vipnames,
                        resource,
                        data,
                        'response',
                        response
                    )

    if vip6:
        path = 'firewall'
        name = 'vip6'
        resource = 'ssl-certificate'
        vipnames = []
        data = {resource: certname}
        if (not vipname) and oldcertname:
            if verbose:
                print('Finding vips with {0} in the certname'.format(oldcertname))
            vipnames = find_vips(fortiapi, oldcertname, name, vdom=vdom, verbose=verbose)
        if vipname:
            vipnames.append(vipname)
        if vipnames:
            for item in vipnames:
                response = fortiapi.put(path, name, mkey=item, vdom=vdom, data=data)
                if verbose:
                    print(
                        path,
                        name,
                        vipnames,
                        resource,
                        data,
                        'response',
                        response
                    )

    if sslvpn:
        path = 'vpn.ssl'
        name = 'settings'
        resource = 'servercert'
        data = {resource: certname}
        response = fortiapi.put(path, name, vdom=vdom, data=data)
        if verbose:
            print(
                path,
                name,
                resource,
                data,
                'response',
                response
            )

    if adminui:
        path = 'system'
        name = 'global'
        resource = 'admin-server-cert'
        data = {resource: certname}
        response = fortiapi.put(path, name, data=data)
        if verbose:
            print(
                path,
                name,
                resource,
                data,
                'response',
                response
            )

    if userauth:
        path = 'system'
        name = 'global'
        resource = 'user-server-cert'
        data = {resource: certname}
        response = fortiapi.put(path, name, data=data)
        if verbose:
            print(
                path,
                name,
                resource,
                data,
                'response',
                response
            )


config_file = '/etc/forticert/forticert.conf'

parser = argparse.ArgumentParser()

parser.add_argument(
        '-H',
        '--host',
        help='hostname or ip address of the device, and alternate http/s port if applicable, for instance 192.168.1.99:8443',
        type=str
)

parser.add_argument(
        '--config',
        help='configuration file if different than /etc/forticert/forticert.conf',
        type=str
)

parser.add_argument(
        '-A',
        '--apitoken',
        help='api token for the device',
        type=str
)

parser.add_argument(
        '-U',
        '--username',
        help='administrative user for the device',
        type=str
)

parser.add_argument(
        '-P',
        '--password',
        help='password for the user,will prompt for password if user exists and password does not',
        type=str
)

parser.add_argument(
        '-n',
        '--certname',
        help='''The name or partial name of the new certificate to use.
        If multiple certificates have the name in them, the one with the latest update will be used''',
        type=str
)

parser.add_argument(
        '-o',
        '--oldcertname',
        help='The name of the certificate to be replaced to search for.',
        type=str
)

parser.add_argument(
        '-s',
        '--scope',
        help='scope of the import, defaults to global, ex: scope vdom',
        type=str
)

parser.add_argument(
        '-V',
        '--verify',
        help='verify ssl. Set to False by default',
        action='store_true'
)

parser.add_argument(
        '-v',
        '--verbose',
        help='turn on verbosity',
        action='store_true'
)

parser.add_argument(
        '--adminui',
        help='check administration console certificate and replace if new certificate name search is newer than the current certificate',
        action='store_true'
)

parser.add_argument(
        '--sslvpn',
        help='check ssl vpn certificate and replace if new certificate name search is newer than the current certificate',
        action='store_true'
)

parser.add_argument(
        '--userauth',
        help='check user authentication certificate and replace if new certificate name search is newer than the current certificate',
        action='store_true'
)

parser.add_argument(
        '--vdom',
        help='set the vdom. root by default',
        type=str
)

parser.add_argument(
        '--vip',
        help='''change the certificate in a vip, or loadbalancer virtual server.
        Use with --vipname if you want a specific rule changed,
        otherwise oldcertname will be used to find the correct certificate to replace''',
        action='store_true'
)

parser.add_argument(
        '--vip6',
        help='''change the certificate in an ipv6 vip, or loadbalancer virtual server.
        Use with --vipname if you want a specific rule changed,
        otherwise oldcertname will be used to find the correct certificate to replace''',
        action='store_true'
)

parser.add_argument(
        '--vipname',
        help='set the vipname for the vip and vip6 argument.',
        type=str
)

args = parser.parse_args()

if args.config:
    config_file = args.config

config = configparser.ConfigParser()
config.read(config_file)

configDefaults = __getConfSection__(config, 'Defaults')

host = __getArg__(configDefaults, args.host, 'host')

apitoken = __getArg__(configDefaults, args.apitoken, 'apitoken')

username = __getArg__(configDefaults, args.username, 'username')

if username:
    password = __getArg__(configDefaults, args.password, 'password')
    if not password:
        password = getpass()

certname = __getArg__(configDefaults, args.certname, 'certname')

oldcertname = __getArg__(configDefaults, args.oldcertname, 'oldcertname')

scope = __getArg__(configDefaults, args.scope, 'scope')

sslvpn = __getArg__(configDefaults, args.sslvpn, 'sslvpn', arg_default=False)

adminui = __getArg__(configDefaults, args.adminui, 'adminui', arg_default=False)

userauth = __getArg__(configDefaults, args.userauth, 'userauth', arg_default=False)

vdom = __getArg__(configDefaults, args.vdom, 'vdom')

verify = __getArg__(configDefaults, args.verify, 'verify', arg_default=False)

vip = __getArg__(configDefaults, args.vip, 'vip', arg_default=False)

vip6 = __getArg__(configDefaults, args.vip6, 'vip6', arg_default=False)

vipname = __getArg__(configDefaults, args.vipname, 'vipname')

verbose = args.verbose
# create certificate change FortiOSAPI object
fortiapi = FortiOSAPI()
fortiapi._session.verify = verify
if verbose:
    fortiapi.debug('on')

# login to object via api token or username and password
if apitoken:
    print('login via api')
    fortiapi.tokenlogin(host, apitoken)
elif username:
    # if password is an empty string, ask for the password
    while password == '':
        password = getpass()
    if password != '':
        print('login via provided password')
        fortiapi.login(host, username, password)
else:
    print("Please provide credentials")

if host and certname:
    changecert(
        fortiapi,
        certname,
        oldcertname=oldcertname,
        vip=vip,
        vip6=vip6,
        sslvpn=sslvpn,
        adminui=adminui,
        userauth=userauth,
        vipname=vipname,
        scope=scope,
        vdom=vdom,
        verbose=verbose
    )

else:
    print('please provide a host and certname')
