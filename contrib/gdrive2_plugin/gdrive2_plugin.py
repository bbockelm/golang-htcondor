#!/usr/bin/env python3
#
# HTCondor file transfer plugin for Google Drive, addressed by file ID.
#
# Destined for upstream HTCondor as a sibling of (eventually a replacement
# for) src/condor_scripts/gdrive_plugin.py. It lives here until then; see
# the README beside it.
#
# WHY THIS EXISTS
#
# The stock gdrive plugin addresses files by PATH -- gdrive://Folder/f.csv --
# and resolves that path by LISTING Drive: get_object_id() queries
# /files?q=name = '...' and '<parent>' in parents, walking down from the root.
#
# Listing requires a broad Drive scope. The narrow scope, drive.file, grants
# an application access only to the files the user explicitly picked for it
# (through the Google Picker) or that it created itself. Under drive.file the
# path walk fails even for a file the application can perfectly well read,
# because it cannot see the FOLDERS on the way to it.
#
# That matters for two independent reasons:
#
#   * Blast radius. In a direct transfer the token lands in $_CONDOR_CREDS on
#     an execute node, which on a shared pool is a machine the submitter does
#     not control. A leaked drive.readonly token exposes the user's entire
#     Drive; a leaked drive.file token exposes the handful of files they
#     picked for that job.
#   * Compliance. Broad Drive scopes are "restricted" and oblige the
#     application to an annual third-party security assessment. drive.file
#     is not restricted.
#
# So the narrow scope is what an access point should ask for, and a plugin
# that can only address files by path cannot use it. This one addresses them
# by ID, which is what the Picker hands back anyway.
#
# THE UPLOAD BUG THIS ALSO FIXES
#
# The stock plugin's upload path calls
#
#     get_parent_folders_ids(folder_tree, create_if_missing = True)
#
# Under drive.file it cannot SEE the user's existing MyProject/results/, so
# create_if_missing does exactly what it says and makes a second one, owned
# by the application, shadowing the real folder. The user's output goes
# somewhere that looks right in the plugin's logs and is not where they
# expected. That is a silent wrong answer rather than an error, which is the
# worst way for this to fail, and it is why this plugin never creates a
# folder and never walks a path.

import json
import mimetypes
import os
import posixpath
import random
import socket
import sys
import time
from urllib.parse import urlparse

import requests
import classad2 as classad

TOKEN_DIR_ENV_NAME = '_CONDOR_CREDS'
TOKEN_FILE_EXT = '.use'

DEFAULT_TIMEOUT = 30

GDRIVE2_PLUGIN_VERSION = '2.0.0'

GDRIVE_API_VERSION = 'v3'
GDRIVE_API_BASE_URL = 'https://www.googleapis.com/drive/' + GDRIVE_API_VERSION
GDRIVE_UPLOAD_URL = 'https://www.googleapis.com/upload/drive/' + GDRIVE_API_VERSION + '/files'

# The method this plugin advertises.
#
# Deliberately NOT "gdrive". A job may carry its own plugin
# (transfer_plugins), and claiming a method the stock plugin already
# advertises would collide with it on every execute node that has one -- which
# is every execute node: measured, all 14552 CHTC slots and all 246 PATh
# Facility slots advertise gdrive. A distinct method lets this be tried by a
# single job, on unmodified machines, before anything is deployed anywhere.
#
# Upstream may well prefer to fold ID addressing into the gdrive method
# instead, using an empty authority (gdrive:///<id>/<name>) to tell the two
# forms apart. That is a better end state and a worse way to get there.
SUPPORTED_METHOD = 'gdrive2'

# The CREDENTIAL this plugin reads is still "gdrive".
#
# The method name and the credential name are different things, and conflating
# them would oblige every user of this plugin to hold a second, identical
# Google credential under a second name -- a second consent screen, a second
# grant to revoke, for no reason but a plugin version number. A job says
# `use_oauth_services = gdrive` whichever plugin it uses.
#
# This is the DEFAULT. A URL may name its credential outright with
# `<cred>+gdrive2://`, which is how a server provisioning into a credd it
# shares with an administrator reaches a credential it had to store under a
# service name of its own. See get_token_name.
CREDENTIAL_NAME = 'gdrive'

# Transient HTTP statuses worth retrying. 429 is Drive's rate limit, which it
# applies per user and per project and which a many-proc cluster WILL hit.
RETRY_STATUSES = frozenset([429, 500, 502, 503, 504])
MAX_ATTEMPTS = 5


def print_help(stream=sys.stderr):
    help_msg = '''Usage: {0} -infile <input-filename> -outfile <output-filename>
       {0} -classad

Options:
  -classad                    Print a ClassAd containing the capabilities of
                              this file transfer plugin.
  -infile <input-filename>    Input ClassAd file
  -outfile <output-filename>  Output ClassAd file
  -upload                     Upload rather than download

URL forms:
  {1}://<fileId>/<name>          download that file, saved as <name>
  {1}://<folderId>/<name>        upload, creating/replacing <name> in that folder
  {1}:///<name>                  upload into My Drive root

  <cred>+{1}://...               read the credential <cred>.use (verbatim)

<name> is the job's local file name. HTCondor takes it from the last path
component of the URL ("the destination file is given by the file name within
the URL"), so it has to be there even though Drive identifies the file by id.
'''
    stream.write(help_msg.format(sys.argv[0], SUPPORTED_METHOD, CREDENTIAL_NAME))


def print_capabilities():
    capabilities = {
        'MultipleFileSupport': True,
        'PluginType': 'FileTransfer',
        'SupportedMethods': SUPPORTED_METHOD,
        'Version': GDRIVE2_PLUGIN_VERSION,
    }
    sys.stdout.write(classad.ClassAd(capabilities).printOld())


def parse_args():
    '''Rolled by hand for the same reason the stock plugin rolls its own: the
    argument shapes the file transfer machinery sends defeat optparse, and a
    plugin should not reach outside the standard library.'''

    if len(sys.argv) == 2 and sys.argv[1] == '-classad':
        print_capabilities()
        sys.exit(0)

    if len(sys.argv) == 2 and sys.argv[1] in ('-h', '-help', '--help'):
        print_help(sys.stdout)
        sys.exit(0)

    infile = None
    outfile = None
    is_upload = False

    args = list(sys.argv[1:])
    while args:
        arg = args.pop(0)
        if arg == '-upload':
            is_upload = True
        elif arg == '-infile':
            if not args:
                print_help()
                sys.exit(1)
            infile = args.pop(0)
        elif arg == '-outfile':
            if not args:
                print_help()
                sys.exit(1)
            outfile = args.pop(0)
        else:
            print_help()
            sys.exit(1)

    if infile is None or outfile is None:
        print_help()
        sys.exit(1)

    return {'infile': infile, 'outfile': outfile, 'upload': is_upload}


def get_token_name(url):
    '''The credential to read, from the URL's scheme.

    `<cred>+gdrive2://...` reads `<cred>.use`, VERBATIM. A bare scheme
    reads gdrive.

    This differs from the stock gdrive plugin, where `<handle>+gdrive://`
    means the composed name `<provider>_<handle>`. The difference is
    deliberate. A server that provisions credentials into a credd it
    shares with an administrator has to store them under a service name
    of its own -- `webapi_gdrive`, say -- and the composing form cannot
    reach that name: it would need the provider half to be `webapi`,
    which is not a transfer method.

    It is safe for the two plugins to read the same syntax differently
    because they never see the same URL. The method differs, so no URL is
    ambiguous between them. It would not be safe if this plugin ever
    claimed the `gdrive` method, which is one more reason it does not.'''
    scheme = url.split('://')[0]
    if '+' in scheme:
        (cred, _method) = scheme.split('+', 1)
        if not cred:
            raise ValueError(
                "empty credential name in '{0}': expected "
                "<cred>+{1}://...".format(url, SUPPORTED_METHOD))
        return cred
    return CREDENTIAL_NAME


def get_token_path(token_name):
    if TOKEN_DIR_ENV_NAME not in os.environ:
        raise KeyError(
            "Required variable '{0}' was not found in job's environment. A job "
            "using {1}:// must ask for the credential with "
            "`use_oauth_services = {2}`".format(
                TOKEN_DIR_ENV_NAME, SUPPORTED_METHOD, CREDENTIAL_NAME))

    cred_dir = os.environ[TOKEN_DIR_ENV_NAME]
    token_path = os.path.join(cred_dir, token_name + TOKEN_FILE_EXT)

    if not os.path.exists(token_path):
        raise IOError(2, 'Token file not found', token_path)

    return token_path


def parse_drive_url(url):
    '''Split a gdrive2 URL into (object_id, name).

    object_id is the file id for a download and the PARENT FOLDER id for an
    upload; an empty one means My Drive root. name is the job's local file
    name.

    No listing, no path walk, no folder creation -- that is the whole point of
    this plugin. A URL with more than one path component is refused rather
    than silently reinterpreted, because under drive.file the only thing this
    plugin could do with a path is guess.'''
    parsed = urlparse(url)

    object_id = parsed.netloc
    path = parsed.path

    if not path or path == '/':
        raise ValueError(
            "{0} names no file: expected {1}://<id>/<name>, got '{2}'".format(
                SUPPORTED_METHOD, SUPPORTED_METHOD, url))

    components = [c for c in posixpath.split(path.lstrip('/')) if c != '']
    if len(components) != 1:
        raise ValueError(
            "{0} does not take a path. Address the file by its Drive id: "
            "{1}://<id>/<name>, not '{2}'".format(
                SUPPORTED_METHOD, SUPPORTED_METHOD, url))

    return (object_id, components[0])


def format_error(error):
    return '{0}: {1}'.format(type(error).__name__, str(error))


def get_error_dict(error, url=''):
    return {
        'TransferSuccess': False,
        'TransferError': format_error(error),
        'TransferUrl': url,
    }


class GDrive2Plugin:

    def __init__(self, token_path):
        self.token_path = token_path
        self.headers = {}
        self.reload_token()

    def reload_token(self):
        '''Re-read the token before every request.

        The starter refreshes credentials into a running job's sandbox on a
        timer (SEC_CREDENTIAL_REFRESH, 300s by default), so a long transfer
        can outlive the token it started with. Caching it in memory is how a
        multi-hour upload fails at the end.'''
        with open(self.token_path, 'r') as f:
            access_token = json.load(f)['access_token']
        self.headers = {'Authorization': 'Bearer {0}'.format(access_token)}

    def request(self, method, url, **kwargs):
        '''One Drive API call, with backoff on the statuses Drive uses to mean
        "later".

        Drive rate-limits per user and per project, so a cluster of a few
        hundred procs each pulling an input is a thundering herd by
        construction. The jitter is not decoration: without it the herd
        retries in lockstep.'''
        kwargs.setdefault('timeout', DEFAULT_TIMEOUT)

        last_response = None
        for attempt in range(MAX_ATTEMPTS):
            self.reload_token()
            headers = dict(self.headers)
            headers.update(kwargs.pop('headers', {}))

            response = requests.request(method, url, headers=headers, **kwargs)
            if response.status_code not in RETRY_STATUSES:
                return response

            last_response = response
            if attempt < MAX_ATTEMPTS - 1:
                # Honour Retry-After when Drive sends one; it knows better
                # than the backoff curve does.
                delay = None
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = None
                if delay is None:
                    delay = (2 ** attempt) + random.random()
                if response.raw is not None:
                    response.close()
                time.sleep(delay)

        return last_response

    @staticmethod
    def describe_http_error(response):
        '''Drive's errors are JSON and its messages are usually the actual
        reason. Surfacing them beats "403 Client Error" in a hold reason.'''
        detail = ''
        try:
            body = response.json()
            detail = body.get('error', {}).get('message', '')
            reasons = [
                e.get('reason', '')
                for e in body.get('error', {}).get('errors', [])
            ]
            reasons = [r for r in reasons if r]
            if reasons:
                detail = '{0} ({1})'.format(detail, ', '.join(reasons))
        except Exception:
            detail = (response.text or '')[:200]

        hint = ''
        if response.status_code == 404:
            hint = (
                ". Under the drive.file scope a file is reachable only after "
                "the user has picked it for this application, so a 404 here "
                "usually means the grant is missing rather than the file")
        elif response.status_code == 403 and 'fileNotDownloadable' in detail:
            hint = (
                ". Google-native documents (Docs, Sheets, Slides) have no "
                "bytes to download and must be exported to a chosen format, "
                "which this plugin does not do")

        return 'Drive API returned {0}: {1}{2}'.format(
            response.status_code, detail, hint)

    def raise_for_status(self, response):
        if response is None:
            raise IOError('no response from the Drive API')
        if response.status_code >= 400:
            raise IOError(self.describe_http_error(response))

    def download_file(self, url, local_file_path):
        start_time = time.time()

        (file_id, _name) = parse_drive_url(url)
        if not file_id:
            raise ValueError(
                "{0} download needs a file id: {1}://<fileId>/<name>".format(
                    SUPPORTED_METHOD, SUPPORTED_METHOD))

        api_url = '{0}/files/{1}'.format(GDRIVE_API_BASE_URL, file_id)

        connection_start_time = time.time()
        response = self.request(
            'GET', api_url,
            params={'alt': 'media', 'supportsAllDrives': 'true'},
            stream=True)

        try:
            self.raise_for_status(response)

            try:
                content_length = int(response.headers['Content-Length'])
            except (ValueError, KeyError, TypeError):
                content_length = False

            with open(local_file_path, 'wb') as f:
                file_size = 0
                for chunk in response.iter_content(chunk_size=8192):
                    file_size += len(chunk)
                    f.write(chunk)
        except Exception:
            # Streaming: free the connection before the exception leaves.
            if response is not None:
                response.close()
            raise

        end_time = time.time()

        # TransferUrl is deliberately omitted, as in the stock plugin: the
        # resolved URL is short-lived and carries authorization, and this ad
        # lands in the transfer history log.
        return {
            'TransferSuccess': True,
            'TransferProtocol': 'https',
            'TransferType': 'download',
            'TransferFileName': local_file_path,
            'TransferFileBytes': file_size,
            'TransferTotalBytes': content_length or file_size,
            'TransferStartTime': int(start_time),
            'TransferEndTime': int(end_time),
            'ConnectionTimeSeconds': end_time - connection_start_time,
            'TransferHostName': urlparse(GDRIVE_API_BASE_URL).netloc,
            'TransferLocalMachineName': socket.gethostname(),
        }

    def find_own_file(self, parent_id, name):
        '''The id of a file called `name` in `parent_id` that this application
        can already see, or None.

        Under drive.file this query is narrow by construction: Drive returns
        only files this application created or was given, so "already there"
        can only mean "we put it there on an earlier run". That is exactly the
        set we may overwrite, and nothing else is visible to overwrite by
        mistake. Under a broader scope the same query would also find the
        user's own unrelated files, which is one more reason to run narrow.'''
        escaped = name.replace('\\', '\\\\').replace("'", "\\'")
        query = "name = '{0}' and trashed = false".format(escaped)
        if parent_id:
            query += " and '{0}' in parents".format(parent_id)
        else:
            query += " and 'root' in parents"

        response = self.request(
            'GET', '{0}/files'.format(GDRIVE_API_BASE_URL),
            params={
                'q': query,
                'fields': 'files(id,name)',
                'pageSize': 10,
                'supportsAllDrives': 'true',
            })
        self.raise_for_status(response)

        files = response.json().get('files', [])
        for entry in files:
            if entry.get('name') == name:
                return entry.get('id')
        return None

    def upload_file(self, url, local_file_path):
        start_time = time.time()

        (parent_id, name) = parse_drive_url(url)

        existing_id = self.find_own_file(parent_id, name)

        metadata = {'name': name}
        if existing_id is None and parent_id:
            # parents may only be set at create time; an update that tries to
            # set it is rejected.
            metadata['parents'] = [parent_id]

        content_type = mimetypes.guess_type(local_file_path)[0] \
            or 'application/octet-stream'

        connection_start_time = time.time()
        with open(local_file_path, 'rb') as f:
            files = (
                ('metadata', (None, json.dumps(metadata), 'application/json')),
                ('file', (name, f, content_type)),
            )
            if existing_id is None:
                response = self.request(
                    'POST', GDRIVE_UPLOAD_URL,
                    params={'uploadType': 'multipart',
                            'supportsAllDrives': 'true'},
                    files=files)
            else:
                response = self.request(
                    'PATCH', '{0}/{1}'.format(GDRIVE_UPLOAD_URL, existing_id),
                    params={'uploadType': 'multipart',
                            'supportsAllDrives': 'true'},
                    files=files)

        self.raise_for_status(response)

        end_time = time.time()

        try:
            file_size = os.stat(local_file_path).st_size
        except OSError:
            file_size = 0

        return {
            'TransferSuccess': True,
            'TransferProtocol': 'https',
            'TransferType': 'upload',
            'TransferFileName': local_file_path,
            'TransferFileBytes': file_size,
            'TransferTotalBytes': file_size,
            'TransferStartTime': int(start_time),
            'TransferEndTime': int(end_time),
            'ConnectionTimeSeconds': end_time - connection_start_time,
            'TransferHostName': urlparse(GDRIVE_UPLOAD_URL).netloc,
            'TransferLocalMachineName': socket.gethostname(),
        }


def main():
    args = parse_args()

    try:
        with open(args['infile'], 'r') as infile:
            infile_ads = classad.parseAds(infile)
    except Exception as err:
        try:
            with open(args['outfile'], 'w') as outfile:
                outfile.write(str(classad.ClassAd(get_error_dict(err))))
        except Exception:
            pass
        sys.exit(1)

    exit_code = 0
    try:
        running_plugins = {}
        with open(args['outfile'], 'w') as outfile:
            for ad in infile_ads:
                try:
                    token_name = get_token_name(ad['Url'])
                    token_path = get_token_path(token_name)

                    if token_path in running_plugins:
                        gdrive = running_plugins[token_path]
                    else:
                        gdrive = GDrive2Plugin(token_path)
                        running_plugins[token_path] = gdrive

                    if not args['upload']:
                        outfile_dict = gdrive.download_file(
                            ad['Url'], ad['LocalFileName'])
                    else:
                        outfile_dict = gdrive.upload_file(
                            ad['Url'], ad['LocalFileName'])

                    outfile.write(str(classad.ClassAd(outfile_dict)))

                except Exception as err:
                    try:
                        outfile.write(str(classad.ClassAd(
                            get_error_dict(err, url=ad.get('Url', '')))))
                    except Exception:
                        pass
                    exit_code = 1
    except Exception as err:
        try:
            with open(args['outfile'], 'w') as outfile:
                outfile.write(str(classad.ClassAd(get_error_dict(err))))
        except Exception:
            pass
        sys.exit(1)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
