#!/usr/bin/env python3
#
# Copyright 2018 Trend Micro and contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
This module provides a request handler that will process web hook events from
Deep Security Smart Check and write a commit status record in Github.

The image must have a label that references the commit.
The repository in Github must be the same as the repository in the registry.

See also:
- https://docs.docker.com/engine/reference/builder/#label
- https://developer.github.com/v3/repos/statuses
"""

from http.server import HTTPServer, BaseHTTPRequestHandler, HTTPStatus
from urllib.parse import urljoin

import json
import hashlib
import hmac
import os

from github import Github

# URL_BASE is the base URL for your Deep Security Smart Check installation.
# It will be used to convert the relative URL from the scan results into an absolute URL
# that will be attached to the commit status.
URL_BASE = os.environ.get('URL_BASE', 'https://example.com/')

ADDRESS = os.environ.get('LISTEN_ADDRESS', '')
PORT = int(os.environ.get('LISTEN_PORT', '8080'))
CONTEXT = os.environ.get('CONTEXT', 'Deep Security Smart Check')

COMMIT_LABEL = os.environ.get('COMMIT_LABEL', 'vcs-ref')

DEFAULT_BASE_URL = "https://api.github.com"

MAX_PAYLOAD_SIZE = 5 * 1024 * 1024


class RequestHandler(BaseHTTPRequestHandler):
    """
    Handles POST requests: validate the payload HMAC if a shared secret has been
    defined, check any findings against policy (see `evaluate_findings`), and
    then post the status to Github.
    """

    protocol_version = 'HTTP/1.1'

    def do_POST(self):  # pylint: disable=invalid-name
        """Handle the POST from the web hook and write a commit status record."""
        try:
            # Get the (authenticated) body as parsed JSON
            event = self.json_body()

            # We are only interested in the `scan-completed` event
            if event['event'] != 'scan-completed':
                self.respond(HTTPStatus.OK)
                return

            scan_url = urljoin(URL_BASE, event['scan']['href'])

            registry = event['scan']['source']['registry']
            repository = event['scan']['source']['repository']
            tag = event['scan']['source']['tag']
            digest = event['scan']['details']['digest']

            ref = event['scan']['details']['labels'].get(COMMIT_LABEL, None)

            self.log_message('Processing results for image %s/%s:%s@%s',
                             registry, repository, tag, digest)

            if ref is None:
                self.log_error('image does not have a %s label, skipping' %
                               COMMIT_LABEL)
                self.respond(HTTPStatus.OK)
                return

            status = evaluate_findings(event['scan']['findings'])

            self.log_message('Image scan status: %s', status)

            github_client = Github(base_url=os.environ.get('GITHUB_URL', DEFAULT_BASE_URL),
                                   login_or_token=os.environ['GITHUB_TOKEN'])

            commit = github_client.get_repo(repository).get_commit(ref)

            commit.create_status(status, context=CONTEXT, target_url=scan_url)

            self.respond(HTTPStatus.OK)
        except InvalidPayloadSizeException:
            self.log_error('Invalid payload size for request')
            self.respond(HTTPStatus.BAD_REQUEST)
        except BadHMACException:
            self.log_error('Invalid HMAC for request')
            self.respond(HTTPStatus.UNAUTHORIZED)
        except KeyError as exception:
            self.log_error('Did not find expected key: %s', exception)
            self.respond(HTTPStatus.BAD_REQUEST)
        except Exception as exception:  # pylint: disable=broad-except
            self.log_error('Unexpected exception: %s', exception)
            self.respond(HTTPStatus.INTERNAL_SERVER_ERROR)

    def json_body(self):
        """Parse the event payload and validate the HMAC against the shared secret."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0 or content_length > MAX_PAYLOAD_SIZE:
            raise InvalidPayloadSizeException()

        content = self.rfile.read(content_length)

        hmac_secret = os.environ.get('HMAC_SECRET', None)

        if hmac_secret is not None:
            actual = hmac.new(bytes(hmac_secret, 'utf-8'),
                              msg=bytes(content),
                              digestmod=hashlib.sha256).hexdigest()

            expected = self.headers.get('X-Scan-Event-Signature', '')

            if not hmac.compare_digest(actual, expected):
                raise BadHMACException()

        return json.loads(content)

    def respond(self, status):
        """Respond to the HTTP request with a status code and no body."""
        self.send_response(status)
        self.send_header('Content-Length', 0)
        self.end_headers()
        self.close_connection = True  # pylint: disable=attribute-defined-outside-init

    def send_header(self, keyword, value):
        """Override the superclass behaviour to suppress sending the `Server` header."""
        if keyword != 'Server':
            super(RequestHandler, self).send_header(keyword, value)


class InvalidPayloadSizeException(Exception):
    """Exception raised when either there is not enough or too much payload."""
    pass


class BadHMACException(Exception):
    """Exception raised when HMAC authentication fails."""
    pass


def evaluate_findings(findings):
    """Evaluate the findings of the scan against local policy."""
    total = 0
    total += findings.get('malware', 0)
    total += findings.get('unresolved', {}).get('defcon1', 0)
    total += findings.get('unresolved', {}).get('critical', 0)
    total += findings.get('unresolved', {}).get('high', 0)

    return 'failed' if total > 0 else 'success'


if __name__ == '__main__':
    print('serving at %s:%d' % (ADDRESS, PORT))
    HTTPServer((ADDRESS, PORT), RequestHandler).serve_forever()
