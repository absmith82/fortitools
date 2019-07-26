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
import json
import argparse
import configparser
from getpass import getpass
from base64 import b64encode
from datetime import date


def __getConfSection__(config, section):
    try:
        return config[section]
    except Exception as e:
        return None


def __getArg__(config, cli, arg, arg_default=None):
    if cli:
        return cli
    try:
        return config[arg]
    except Exception:
        return arg_default


def __prepfile__(filename):
    try:
        with open(filename, 'rb') as file:
            file = str(b64encode(file.read()), 'ascii')
            return file
    except Exception as e:
        print(e)



config_file = '/etc/forticert/forticert.conf'

def caimport(
    fortiapi,
    import_method='file',
    cafile=None,
    scope='global',
    vdom='root',
    verify=False,
    verbose=False
):
    """Import a ca certificate to fortios."""
#    Initialize variable needed for CA import.
    if cafile:
        cacert = __prepfile__(cafile)
        data = {'source': 'upload', 'file_content': cacert}
    path = 'vpn-certificate'
    name = 'ca'
    mkey = 'import'
    scope = 'global'
    parameters = {'import_method': import_method, 'scope': scope}
    data = {'source': 'upload', 'file_content': cacert}

    if verbose:
        print(
            path,
            name,
            mkey,
            parameters,
            json.dumps(data)
            )

    upload_response = fortiapi.upload(
        path,
        name,
        mkey=mkey,
        parameters=parameters,
        data=json.dumps(data)
        )

    if verbose:
        print(
            'upload_response',
            upload_response.content,
            upload_response.reason,
        )


def certimport(
    fortiapi,
    certname=None,
    append_date=False,
    certfile=None,
    keyfile=None,
    keypassword=None,
    type='regular',
    scope='global',
    vdom='root',
    verify=False,
    verbose=False
):
    """Import a public and private key certificate for fortios."""
#    Initialize variable needed for CA import.

    path = 'vpn-certificate'
    name = 'local'
    mkey = 'import'
    parameters = {'vdom': vdom, 'type': type, 'scope': scope}
    data = {'source': 'upload'}

    if certfile:
        cert = __prepfile__(certfile)
        data['file_content'] = cert
    if keyfile:
        key = __prepfile__(keyfile)
        data['key_file_content'] = key
    if certname:
        if append_date:
            data['certname'] = certname + str(date.today())
        else:
            data['certname'] = certname
    if keypassword:
        parameters['password'] = keypassword

    if verbose:
        print(
            path,
            name,
            mkey,
            parameters,
            json.dumps(data)
            )

    upload_response = fortiapi.upload(
        path,
        name,
        mkey=mkey,
        parameters=parameters,
        data=json.dumps(data)
        )

    if verbose:
        print(
            'upload_response',
            upload_response
        )


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

# removed since I have no way to test scep server
'''
parser.add_argument(
        '-i',
        '--import_method',
        help='import method either file or scep',
        type=str
)
'''

parser.add_argument(
        '-C',
        '--cafile',
        help='filename and path for ca certificate import.',
        type=str
)

parser.add_argument(
        '-c',
        '--certfile',
        help='filename and path for public key certificate import.',
        type=str
)

parser.add_argument(
        '-k',
        '--keyfile',
        help='filename and path for private key file import.',
        type=str
)

parser.add_argument(
        '-N',
        '--caname',
        help='The name that the ca certificate should have on import.',
        type=str
)

parser.add_argument(
        '-n',
        '--certname',
        help='The name that the public key certificate should have on import. Required if uploading a certificate.',
        type=str
)

parser.add_argument(
        '-d',
        '--append_date',
        help='If the certname should have the date appended to the end of the certificate.',
        action='store_true'
)

parser.add_argument(
        '-p',
        '--keypassword',
        help='password for the private key certificate',
        type=str
)

parser.add_argument(
        '-t',
        '--type',
        help='certificate type for import, [local|pkcs12|regular] default value is regular',
        type=str
)

parser.add_argument(
        '-s',
        '--scope',
        help='scope of the import, defaults to global, ex: scope vdom',
        type=str
)

parser.add_argument(
        '--vdom',
        help='set the vdom. root by default',
        action='store_true'
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

args = parser.parse_args()

if args.config:
    config_file = args.config

config = configparser.ConfigParser()
config.read(config_file)

configDefaults = __getConfSection__(config, 'Defaults')

if args.host:
    host = args.host

apitoken = __getArg__(configDefaults, args.apitoken, 'apitoken')

username = __getArg__(configDefaults, args.username, 'username')

if username:
    password = __getArg__(configDefaults, args.password, 'password')
    if not password:
        password = getpass()

# removed since I have no way to test scep server
'''if args.import_method:
    import_method = args.import_method'''

cafile = __getArg__(configDefaults, args.cafile, 'cafile')

certfile = __getArg__(configDefaults, args.certfile, 'certfile')

append_date = __getArg__(configDefaults, args.append_date, 'append_date')

keyfile = __getArg__(configDefaults, args.keyfile, 'keyfile')

certname = __getArg__(configDefaults, args.certname, 'certname')

keypassword = __getArg__(configDefaults, args.keypassword, 'keypassword')

scope = __getArg__(configDefaults, args.scope, 'scope', arg_default='global')

type = __getArg__(configDefaults, args.type, 'type', arg_default='regular')

verify = __getArg__(configDefaults, args.verify, 'verify', arg_default=False)

for section in config.sections():
    if section != configDefaults:

        configSection = __getConfSection__(config, section)

        host = __getArg__(configSection, args.host, 'apitoken')

        apitoken = __getArg__(configSection, args.apitoken, 'apitoken')

        username = __getArg__(configSection, args.username, 'username')

        if username:
            password = __getArg__(configSection, args.password, 'password')
            if not password:
                password = getpass()

        # removed since I have no way to test scep server
        '''if args.import_method:
            import_method = args.import_method'''

        cafile = __getArg__(
            configSection,
            args.cafile,
            'cafile',
            arg_default=cafile
            )

        certfile = __getArg__(
            configSection,
            args.certfile,
            'certfile',
            arg_default=certfile
            )

        append_date = __getArg__(
            configSection,
            args.append_date,
            'append_date',
            arg_default=append_date
            )

        keyfile = __getArg__(
            configSection,
            args.keyfile,
            'keyfile',
            arg_default=keyfile
            )

        certname = __getArg__(
            configSection,
            args.certname,
            'certname',
            arg_default=certname
            )

        keypassword = __getArg__(
            configSection,
            args.keypassword,
            'keypassword',
            arg_default=keypassword
            )

        scope = __getArg__(
            configSection,
            args.scope,
            'scope',
            arg_default=scope
            )

        type = __getArg__(
            configSection,
            args.type,
            'type',
            arg_default=type
            )

        verify = __getArg__(
            configSection,
            args.verify,
            'verify',
            arg_default=verify
            )

verbose = args.verbose

# create upload certificate FortiOSAPI object
uploadcert = FortiOSAPI()
uploadcert._session.verify = verify
if verbose:
    uploadcert.debug('on')

# login to object via api token or username and password
if apitoken:
    print('login via api')
    uploadcert.tokenlogin(host, apitoken)
elif username:
    # if password is an empty string, ask for the password
    while password == '':
        password = getpass()
    if password != '':
        print('login via provided password')
        uploadcert.login(host, username, password)
else:
    print("Please provide credentials")

if cafile:
    caimport(
        uploadcert,
        import_method=import_method,
        cafile=cafile,
        scope=scope,
        verify=verify,
        verbose=verbose
    )

if certfile:
    certimport(
        uploadcert,
        certname=certname,
        append_date=append_date,
        certfile=certfile,
        keyfile=keyfile,
        keypassword=keypassword,
        type=type,
        scope=scope,
        verify=verify,
        verbose=verbose
    )
