#!/usr/bin/env python3
"""Tests for gdrive2_plugin, against a stand-in for the Drive API.

Run:  python3 -m unittest test_gdrive2_plugin -v

Needs `requests` and HTCondor's `classad2` on the path; everything else is
the standard library. No network and no Google account: the point is that a
plugin upstream might take should be testable by anyone who checks it out.
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import classad2 as classad

import gdrive2_plugin as gd


# --- a stand-in Drive -------------------------------------------------

class FakeDriveHandler(BaseHTTPRequestHandler):
    """Serves the three endpoints the plugin uses.

    state lives on the server object so a test can rig responses and then
    inspect what the plugin actually sent.
    """

    def log_message(self, *args):
        pass  # keep the test output readable

    def _send(self, code, body, content_type='application/json'):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        for k, v in self.server.extra_headers.items():
            self.send_header(k, v)
        self.wfile.write(b'')
        self.end_headers()
        self.wfile.write(body)

    def _record(self, method):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        self.server.requests.append({
            'method': method,
            'path': self.path,
            'auth': self.headers.get('Authorization'),
            'body': body,
        })
        return body

    def do_GET(self):
        self._record('GET')

        if self.server.statuses:
            code = self.server.statuses.pop(0)
            if code != 200:
                self._send(code, json.dumps({'error': {
                    'message': 'rigged', 'errors': [{'reason': 'rigged'}]}}))
                return

        if self.path.startswith('/drive/v3/files?'):
            # a list query
            self._send(200, json.dumps({'files': self.server.list_result}))
            return

        # a media download
        self._send(200, self.server.file_bytes,
                   content_type='application/octet-stream')

    def do_POST(self):
        self._record('POST')
        if self.server.statuses:
            code = self.server.statuses.pop(0)
            if code != 200:
                self._send(code, json.dumps({'error': {'message': 'rigged'}}))
                return
        self._send(200, json.dumps({'id': 'created-id', 'name': 'x'}))

    def do_PATCH(self):
        self._record('PATCH')
        self._send(200, json.dumps({'id': 'updated-id', 'name': 'x'}))


class FakeDrive:
    def __init__(self):
        self.httpd = HTTPServer(('127.0.0.1', 0), FakeDriveHandler)
        self.httpd.requests = []
        self.httpd.statuses = []
        self.httpd.list_result = []
        self.httpd.file_bytes = b''
        self.httpd.extra_headers = {}
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()

    @property
    def base(self):
        host, port = self.httpd.server_address
        return 'http://{0}:{1}'.format(host, port)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# --- the fixture ------------------------------------------------------

class PluginTestCase(unittest.TestCase):

    def setUp(self):
        self.drive = FakeDrive()
        self.tmp = tempfile.mkdtemp(prefix='gdrive2test')

        self.creds = os.path.join(self.tmp, 'creds')
        os.makedirs(self.creds)
        self.write_token('gdrive', 'token-one')
        os.environ[gd.TOKEN_DIR_ENV_NAME] = self.creds

        self._saved = (gd.GDRIVE_API_BASE_URL, gd.GDRIVE_UPLOAD_URL)
        gd.GDRIVE_API_BASE_URL = self.drive.base + '/drive/v3'
        gd.GDRIVE_UPLOAD_URL = self.drive.base + '/upload/drive/v3/files'

    def tearDown(self):
        gd.GDRIVE_API_BASE_URL, gd.GDRIVE_UPLOAD_URL = self._saved
        os.environ.pop(gd.TOKEN_DIR_ENV_NAME, None)
        self.drive.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_token(self, name, value):
        path = os.path.join(self.creds, name + gd.TOKEN_FILE_EXT)
        with open(path, 'w') as f:
            json.dump({'access_token': value}, f)
        return path

    def plugin(self, name='gdrive'):
        return gd.GDrive2Plugin(os.path.join(
            self.creds, name + gd.TOKEN_FILE_EXT))

    def requests_of(self, method):
        return [r for r in self.drive.httpd.requests if r['method'] == method]


# --- URL grammar ------------------------------------------------------

class TestURLGrammar(unittest.TestCase):

    def test_id_and_name(self):
        self.assertEqual(gd.parse_drive_url('gdrive2://abc123/data.csv'),
                         ('abc123', 'data.csv'))

    def test_empty_authority_means_root(self):
        self.assertEqual(gd.parse_drive_url('gdrive2:///out.dat'),
                         ('', 'out.dat'))

    def test_a_path_is_refused_not_reinterpreted(self):
        # The stock plugin would walk this. Under drive.file the walk cannot
        # work, and guessing is worse than refusing.
        with self.assertRaises(ValueError) as cm:
            gd.parse_drive_url('gdrive2://Folder/Sub/data.csv')
        self.assertIn('does not take a path', str(cm.exception))

    def test_no_filename_is_refused(self):
        for url in ('gdrive2://abc123', 'gdrive2://abc123/'):
            with self.assertRaises(ValueError):
                gd.parse_drive_url(url)

    def test_credential_name_is_the_service_not_the_plugin(self):
        # The whole point: v2 must not oblige anyone to hold a second
        # Google credential under a second name.
        self.assertEqual(gd.get_token_name('gdrive2://x/y'), 'gdrive')

    def test_a_prefix_names_the_credential_verbatim(self):
        # NOT gdrive_webapi. The stock plugin composes <provider>_<handle>
        # and so cannot reach a credential stored under a service name of
        # the server's own, which is the case this exists for.
        self.assertEqual(gd.get_token_name('webapi_gdrive+gdrive2://x/y'),
                         'webapi_gdrive')

    def test_an_empty_credential_name_is_refused(self):
        with self.assertRaises(ValueError):
            gd.get_token_name('+gdrive2://x/y')


# --- download ---------------------------------------------------------

class TestDownload(PluginTestCase):

    def test_writes_the_file_and_reports_bytes(self):
        self.drive.httpd.file_bytes = b'hello drive' * 100
        dest = os.path.join(self.tmp, 'data.csv')

        stats = self.plugin().download_file('gdrive2://fileid/data.csv', dest)

        self.assertTrue(stats['TransferSuccess'])
        self.assertEqual(stats['TransferType'], 'download')
        with open(dest, 'rb') as f:
            self.assertEqual(f.read(), self.drive.httpd.file_bytes)
        self.assertEqual(stats['TransferFileBytes'],
                         len(self.drive.httpd.file_bytes))

    def test_addresses_by_id_and_never_lists(self):
        self.drive.httpd.file_bytes = b'x'
        self.plugin().download_file('gdrive2://THEID/f.bin',
                                    os.path.join(self.tmp, 'f.bin'))

        paths = [r['path'] for r in self.requests_of('GET')]
        self.assertEqual(len(paths), 1, 'a download should be one request')
        self.assertIn('/files/THEID', paths[0])
        # No q= anywhere: listing is what drive.file withholds.
        self.assertNotIn('q=', paths[0])

    def test_no_transfer_url_in_the_ad(self):
        # It would put a short-lived authorizing URL in the transfer history.
        self.drive.httpd.file_bytes = b'x'
        stats = self.plugin().download_file('gdrive2://i/f',
                                            os.path.join(self.tmp, 'f'))
        self.assertNotIn('TransferUrl', stats)

    def test_404_explains_the_drive_file_grant(self):
        self.drive.httpd.statuses = [404]
        with self.assertRaises(IOError) as cm:
            self.plugin().download_file('gdrive2://missing/f',
                                        os.path.join(self.tmp, 'f'))
        self.assertIn('picked it for this application', str(cm.exception))

    def test_download_needs_an_id(self):
        with self.assertRaises(ValueError):
            self.plugin().download_file('gdrive2:///f',
                                        os.path.join(self.tmp, 'f'))


# --- upload -----------------------------------------------------------

class TestUpload(PluginTestCase):

    def setUp(self):
        super().setUp()
        self.src = os.path.join(self.tmp, 'result.dat')
        with open(self.src, 'wb') as f:
            f.write(b'results' * 10)

    def test_creates_in_the_named_parent(self):
        stats = self.plugin().upload_file('gdrive2://PARENT/result.dat',
                                          self.src)
        self.assertTrue(stats['TransferSuccess'])
        self.assertEqual(stats['TransferType'], 'upload')

        posts = self.requests_of('POST')
        self.assertEqual(len(posts), 1)
        body = posts[0]['body'].decode('utf-8', 'replace')
        self.assertIn('"parents": ["PARENT"]', body)
        self.assertIn('"name": "result.dat"', body)

    def test_never_creates_a_folder(self):
        # The stock plugin's create_if_missing=True builds a shadow folder
        # tree under drive.file. Nothing here may create a folder at all.
        self.plugin().upload_file('gdrive2://PARENT/result.dat', self.src)
        for r in self.drive.httpd.requests:
            body = r['body'].decode('utf-8', 'replace')
            self.assertNotIn('application/vnd.google-apps.folder', body)

    def test_replaces_a_file_it_already_owns(self):
        self.drive.httpd.list_result = [{'id': 'OLDID', 'name': 'result.dat'}]

        self.plugin().upload_file('gdrive2://PARENT/result.dat', self.src)

        self.assertEqual(len(self.requests_of('POST')), 0,
                         'an existing file should be updated, not duplicated')
        patches = self.requests_of('PATCH')
        self.assertEqual(len(patches), 1)
        self.assertIn('OLDID', patches[0]['path'])
        # parents may not be set on an update.
        self.assertNotIn('parents',
                         patches[0]['body'].decode('utf-8', 'replace'))

    def test_empty_authority_uploads_to_root(self):
        self.plugin().upload_file('gdrive2:///result.dat', self.src)
        gets = self.requests_of('GET')
        self.assertTrue(any("root" in r['path'] for r in gets),
                        'a parentless upload should look in My Drive root')

    def test_a_differently_named_match_is_not_a_match(self):
        # Drive's name= query is not exact in every locale; the plugin
        # re-checks rather than trusting it.
        self.drive.httpd.list_result = [{'id': 'OTHER', 'name': 'other.dat'}]
        self.plugin().upload_file('gdrive2://PARENT/result.dat', self.src)
        self.assertEqual(len(self.requests_of('POST')), 1)
        self.assertEqual(len(self.requests_of('PATCH')), 0)


# --- retry and tokens -------------------------------------------------

class TestRetryAndTokens(PluginTestCase):

    def test_retries_a_429_then_succeeds(self):
        self.drive.httpd.extra_headers = {'Retry-After': '0'}
        self.drive.httpd.statuses = [429]
        self.drive.httpd.file_bytes = b'eventually'

        stats = self.plugin().download_file('gdrive2://i/f',
                                            os.path.join(self.tmp, 'f'))

        self.assertTrue(stats['TransferSuccess'])
        self.assertEqual(len(self.requests_of('GET')), 2)

    def test_gives_up_and_reports_the_status(self):
        self.drive.httpd.extra_headers = {'Retry-After': '0'}
        self.drive.httpd.statuses = [503] * gd.MAX_ATTEMPTS
        with self.assertRaises(IOError) as cm:
            self.plugin().download_file('gdrive2://i/f',
                                        os.path.join(self.tmp, 'f'))
        self.assertIn('503', str(cm.exception))
        self.assertEqual(len(self.requests_of('GET')), gd.MAX_ATTEMPTS)

    def test_rereads_the_token_every_request(self):
        # The starter refreshes credentials into a running sandbox on a
        # timer, so a transfer can outlive the token it began with. A
        # plugin that caches the token in memory fails at the end of a long
        # upload, which is the worst moment.
        self.drive.httpd.extra_headers = {'Retry-After': '0'}
        self.drive.httpd.statuses = [503]
        self.drive.httpd.file_bytes = b'x'

        p = self.plugin()
        self.write_token('gdrive', 'token-two')
        p.download_file('gdrive2://i/f', os.path.join(self.tmp, 'f'))

        auths = [r['auth'] for r in self.requests_of('GET')]
        self.assertEqual(auths[-1], 'Bearer token-two',
                         'the refreshed token was not picked up')

    def test_missing_credential_says_what_to_ask_for(self):
        # Through get_token_path, which is what main() calls before it
        # builds a plugin -- constructing one directly would reach the bare
        # open() and lose the message.
        with self.assertRaises(IOError) as cm:
            gd.get_token_path('nosuch')
        self.assertIn('Token file not found', str(cm.exception))

    def test_no_cred_dir_names_the_submit_command(self):
        os.environ.pop(gd.TOKEN_DIR_ENV_NAME)
        with self.assertRaises(KeyError) as cm:
            gd.get_token_path('gdrive')
        self.assertIn('use_oauth_services', str(cm.exception))


# --- the plugin contract ----------------------------------------------

class TestCapabilities(unittest.TestCase):

    def test_advertises_its_own_method_not_gdrive(self):
        # Claiming "gdrive" would collide with the stock plugin, which is
        # installed on every execute node measured. A distinct method is
        # what lets a single job carry this one and try it.
        caps = {
            'MultipleFileSupport': True,
            'PluginType': 'FileTransfer',
            'SupportedMethods': gd.SUPPORTED_METHOD,
            'Version': gd.GDRIVE2_PLUGIN_VERSION,
        }
        ad = classad.ClassAd(caps)
        self.assertEqual(ad['SupportedMethods'], 'gdrive2')
        self.assertNotEqual(ad['SupportedMethods'], 'gdrive')
        self.assertTrue(ad['MultipleFileSupport'])


if __name__ == '__main__':
    unittest.main()
