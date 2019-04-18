#!/usr/bin/env python3
#
# Copyright 2019 Trend Micro and contributors.
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

from __future__ import print_function

import argparse
import os
import sys

from smartcheck import Smartcheck

ALL_SEVERITIES = [
    'defcon1',
    'critical',
    'high',
    'medium',
    'low',
    'negligible',
    'unknown',
]


def get_vector(vector, vulnerability):
    """Get a vector out of the CVSS definition (if present) for a vulnerability."""

    vectors = []

    # Some sources have metadata as { metadata: NVD: CVSSv3: Vectors: "..." }
    # and others have { metadata: CVSSv2: "..." }
    if 'metadata' in vulnerability:
        if 'NVD' in vulnerability['metadata']:
            vectors = vulnerability['metadata']['NVD'].get(
                'CVSSv3', {}).get('Vectors', '').split('/')
            if len(vectors) == 1:
                vectors = vulnerability['metadata']['NVD'].get(
                    'CVSSv2', {}).get('Vectors', '').split('/')
        else:
            cvssV2 = vulnerability['metadata'].get('CVSSv2', None)
            if isinstance(cvssV2, str):
                vectors = cvssV2.split('/')
                # The first element is the score, which we're not using here
                vectors.pop(0)

    found = list(filter(lambda x: vector in x, vectors))
    if found:
        return found[0]

    return None


def sev_list(min_level):
    return ALL_SEVERITIES[:ALL_SEVERITIES.index(min_level)+1]


def parse_args():
    """Parse command-line arguments."""

    # This is split out from the main() function solely so that I can skip over
    # it more easily when going through the code.

    parser = argparse.ArgumentParser(
        description='List vulnerabilities found in scans',
    )

    parser.add_argument(
        '--smartcheck-host',
        action='store',
        default=os.environ.get('DSSC_SMARTCHECK_HOST', None),
        help='The hostname of the Deep Security Smart Check deployment. Example: smartcheck.example.com'
    )

    parser.add_argument(
        '--smartcheck-user',
        action='store',
        default=os.environ.get('DSSC_SMARTCHECK_USER', None),
        help='The userid for connecting to Deep Security Smart Check'
    )

    parser.add_argument(
        '--smartcheck-password',
        action='store',
        default=os.environ.get('DSSC_SMARTCHECK_PASSWORD', None),
        help='The password for connecting to Deep Security Smart Check'
    )

    parser.add_argument(
        '--insecure-skip-tls-verify',
        action='store_true',
        default=os.environ.get('DSSC_INSECURE_SKIP_TLS_VERIFY', False),
        help='Ignore certificate errors when connecting to Deep Security Smart Check'
    )

    parser.add_argument(
        '--min-severity',
        action='store',
        default='high',
        help='The minimum severity of vulnerability to show. Defaults to "high". Values: [defcon1,critical,high,medium,low,negligible,unknown]'
    )

    parser.add_argument(
        '--show-overridden',
        action='store_true',
        help='Show vulnerabilities that have been marked as overridden'
    )

    parser.add_argument(
        '--show-fixed',
        action='store_true',
        help='Show vulnerabilities that have been fixed by a later layer'
    )

    parser.add_argument(
        'image',
        help='The image to scan. Example: registry.example.com/project/image:latest'
    )

    return parser.parse_args()


def main():
    """Mainline"""

    args = parse_args()

    if args.smartcheck_host is None:
        print('smartcheck-host is required', file=sys.stderr)
        sys.exit(1)

    try:
        notable_list = sev_list(args.min_severity)
    except ValueError:
        print('unrecognized severity')
        sys.exit(1)

    with Smartcheck(
        base=args.smartcheck_host,
        verify=(not args.insecure_skip_tls_verify),
        user=args.smartcheck_user,
        password=args.smartcheck_password
    ) as session:
        # list_scans(image) will return a generator that will give us all of the
        # scans for that image if we ask for them. We're only going to ask for one
        # because we only care about the last scan result.
        for scan in session.list_scans(args.image, limit=1):

            # We only want to print out the header if there are notable vulnerabilities,
            # which we won't know until later.
            first = True

            # list_vulnerable_packages(scan) will return a generator that will give
            # us all of the vulnerable packages. Each package will have a list of
            # vulnerabilities.
            for package in session.list_vulnerable_packages(scan):
                name = package.get('name', "-unknown-")

                # Now let's go through the vulnerabilities.
                for vulnerability in package['vulnerabilities']:
                    severity = vulnerability['severity']

                    # Skip low-severity vulnerabilities unless the user wants them
                    if not severity in notable_list:
                        continue

                    # Don't show vulnerabilities that have been fixed
                    if 'fixed' in vulnerability:
                        if not args.show_fixed:
                            continue

                    # Only show overridden vulnerabilities if the user has asked for them
                    if 'override' in vulnerability:
                        if not args.show_overridden:
                            continue

                    cve = vulnerability['name']

                    vector = get_vector('AV:', vulnerability)
                    if vector is not None:
                        # Some sources encode the full vector (for example AV:NETWORK),
                        # others use the abbreviation (AV:N). We'll abbreviate for
                        # consistency.
                        vector = vector[:4]
                    else:
                        vector = '?'

                    # We have a notable vulnerability that we want to display, if
                    # it's the first one we'll add a pretty header
                    if first:
                        print('package         vector severity   vulnerability')
                        print('--------------- ------ ---------- -------------')
                        first = False

                    print(
                        f'{name:{15}} {vector:{6}} {severity:{10}} {cve}'
                    )

            # Only asking for one scan doesn't mean that the iterator won't happily
            # ask for the next one, so stop the loop here.
            break


if __name__ == '__main__':
    main()
