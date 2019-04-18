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

import json

import requests

from docker_image import reference


class _SlightlyImprovedSession(requests.Session):
    """
    A _SlightlyImprovedSession keeps track of the base URL and any kwargs that
    should be passed to requests.

    When you make a `get` or `post` request, the URL you provide will be
    `urljoin`'d with the base URL, so relative URLs will work pretty well.

    Technically, this is totally broken, because relative URLs should be
    evaluated relative to the resource that provided the URL, but for our
    purposes this works perfectly and really simplifies life, so we're
    going to ignore the pedants.
    """

    def __init__(self, base, **kwargs):
        super(_SlightlyImprovedSession, self).__init__()
        self.base = base
        self.kwargs = kwargs

    def post(self, url, **kwargs):
        for k in self.kwargs:
            if k not in kwargs:
                kwargs[k] = self.kwargs[k]

        return super(_SlightlyImprovedSession, self).post(
            requests.compat.urljoin(self.base, url),
            **kwargs
        )

    def get(self, url, **kwargs):
        for k in self.kwargs:
            if k not in kwargs:
                kwargs[k] = self.kwargs[k]

        return super(_SlightlyImprovedSession, self).get(
            requests.compat.urljoin(self.base, url),
            **kwargs
        )

    def delete(self, url, **kwargs):
        for k in self.kwargs:
            if k not in kwargs:
                kwargs[k] = self.kwargs[k]

        return super(_SlightlyImprovedSession, self).delete(
            requests.compat.urljoin(self.base, url),
            **kwargs
        )


class Smartcheck(_SlightlyImprovedSession):
    """
    A Smartcheck object provides some convenience methods for performing actions
    using the Deep Security Smart Check API.
    """

    def __init__(self, base, user, password, verify=True, trace=False, **kwargs):
        """Authenticate with the service and return a session."""
        if not base.startswith('http'):
            base = 'https://' + base

        if not verify:
            import urllib3
            urllib3.disable_warnings()

        # Turn on trace logging if requested
        if trace:
            import logging

            try:
                import http.client as http_client
            except ImportError:
                import httplib as http_client

            http_client.HTTPConnection.debuglevel = 1

            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger('requests.packages.urllib3')
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

        super(Smartcheck, self).__init__(base, verify=verify, **kwargs)

        self.headers.update({'X-Api-Version': '2018-05-01'})

        self.credentials = {
            'user': {
                'userID': user,
                'password': password
            }
        }

    def __enter__(self):
        """
        Context manager method that's called when someone creates a
            with Smartcheck(...) as session:
        block. We'll start the session when the block is entered.
        """

        # Create the session with the credentials that were provided in
        # the constructor.
        response = self.post('/api/sessions', json=self.credentials)

        if not response.ok:
            raise CreateSessionException(response)

        # Parse the created session
        session = response.json()

        # Save the session href (needed for later refreshes (TODO)
        # or to terminate the session when we're done).
        self.session_href = session['href']

        # Put the session token into the `Authorization` header so all
        # requests in this session get authenticated and authorized.
        self.headers.update({
            'Authorization': f'Bearer {session["token"]}'
        })

        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        """
        Context manager method that's called when someone exits a
            with Smartcheck(...) as session:
        block. We'll use this trigger to terminate the session.
        """
        # Send `DELETE {href}` to terminate the session
        self.delete(self.session_href)

        # Don't eat any exception that might be coming...
        return False

    def _list(self, url, exception_kind, key, **kwargs):
        """
        Generic "list anything in Deep Security Smart Check" method. Is a generator that
        will yield the individual items being listed and retrieve additional pages of data
        as needed until there are no more.

        The way listing resources works in the Deep Security Smart Check API is as follows:

            1. Perform `GET /api/things` to get the first page of things.
            2. The response will have the structure `{ things: [...] }`
               and if there is more data there will be a header `Link: <...>;rel="next"`
               that will take you to the next page. If there is no more data,
               the `Link rel=next` header won't be there.

        This method is the generic implementation that all of the `list*` methods will call.
        """

        # Get the first page of results
        response = self.get(url, **kwargs)

        while True:
            # If the request failed, bail out -- we've got a specific exception type
            # for each kind of thing we list, so raise the appropriate exception
            if not response.ok:
                raise exception_kind(response)

            # All of the `list*` responses have the same structure:
            #     { [key]: [items], next: "cursor?" }
            # Use the key to extract the items and yield them one at a time.
            for item in response.json()[key]:
                yield item

            # We use the link in the `Link: rel='next'` header as it's easier
            # than building a URL based on the cursor in the body. If there is
            # no header then there's no more data.
            if not 'next' in response.links:
                break

            # Extract the URL from the `Link: rel='next'` header.
            url = response.links['next']['url']

            # Get the next page of results, we'll see you again at the top of the loop
            response = self.get(url)

    def list_scans(self, image_ref=None, limit=None, **kwargs):
        """List scans that match an image reference."""

        # If the caller provided any parameters (like `limit`), then extract them here
        # as we've got more to add...
        params = kwargs.get('params', {})

        # Delete `params` from `kwargs` as we'll be passing them in explicitly
        if 'params' in kwargs:
            del(kwargs['params'])

        if image_ref is not None:
            # Parse the image reference into its component parts
            image_ref = reference.Reference.parse(image_ref)

            # The "hostname" part still needs to get split into the registry and repository
            registry, repository = image_ref.split_hostname()

            # Add query parameters to search on the image reference bits
            params.update({
                'registry': registry,
                'repository': repository,
                'tag': image_ref['tag'],
                'digest': image_ref['digest'],
                'exact': True,
            })

        if limit is not None:
            params['limit'] = limit

        # Yield the resulting scans
        for scan in self._list('/api/scans', ListScansException, 'scans', params=params, **kwargs):
            yield scan

    def create_scan(self, image_ref, image_pull_auth=None, insecure_skip_registry_tls_verify=False):
        """Start a scan."""

        # Parse the image reference into its component parts
        parsed_ref = reference.Reference.parse(image_ref)

        # The "hostname" part still needs to get split into the registry and repository
        registry, repository = parsed_ref.split_hostname()

        # Parse the provided image_pull_auth into an object if it's a string (assuming JSON).
        # It will get serialized back into JSON in the request momentarily.
        if isinstance(image_pull_auth, str):
            image_pull_auth = json.loads(image_pull_auth)

        # Send the request
        response = self.post('/api/scans',
                             json={
                                 'name': image_ref,
                                 'source': {
                                     'type': 'docker',
                                     'registry': registry,
                                     'repository': repository,
                                     'tag': parsed_ref['tag'],
                                     'digest': parsed_ref['digest'],
                                     'credentials': image_pull_auth,
                                     'insecureSkipVerify': insecure_skip_registry_tls_verify,
                                 }
                             })

        if not response.ok:
            raise CreateScanException(response)

        # Return the parsed scan object
        return response.json()

    def list_malware(self, scan):
        """List the malware found during a scan."""

        # Scan results have malware identified per-layer to help folks identify where
        # in their process they need to resolve the issue. This means we need to go
        # through the layers in order to find any malware findings.
        for layer in scan['details']['results']:
            if 'malware' in layer:
                for package in self._list(layer['malware'], ListMalwareException, 'malware'):
                    yield package

    def list_content_findings(self, scan):
        """List the content findings found during a scan."""

        # Scan results have content findings identified per-layer to help folks identify where
        # in their process they need to resolve the issue. This means we need to go
        # through the layers in order to find any content findings.
        for layer in scan['details']['results']:
            if 'contents' in layer:
                for finding in self._list(layer['contents'], ListContentFindingsException, 'contents'):
                    yield finding

    # Scan results have vulnerabilities identified per-layer (mostly) to help folks identify where
    # in their process they need to resolve the issue. This means we need to go
    # through the layers in order to find any vulnerability findings.
    def list_vulnerable_packages(self, scan):
        """List the vulnerable packages found during a scan."""

        for layer in scan['details']['results']:
            if 'vulnerabilities' in layer:
                for package in self._list(layer['vulnerabilities'], ListVulnerabilitiesException, 'vulnerabilities'):
                    yield package

    # Scan results have checklist findings identified per-checklist and per-profile within
    # each checklist. This means we need to go through each checklist and profile to find
    # all the results.
    def list_checklist_findings(self, scan):
        """List the checklist findings found during a scan."""

        if 'checklists' in scan['details']:
            for checklist in self._list(scan['details']['checklists'], ListChecklistsException, 'checklists'):
                # Save details about the checklist so we can report it with the result
                # without creating a new object for each result. This will help if the
                # consumer wants to re-create the tree.
                checklist_info = {
                    'id': checklist['id'],
                    'href': checklist['href'],
                    'title': checklist.get('title', None),
                    'version': checklist.get('version', None),
                }

                for profile in checklist['profiles']:
                    # Save details about the profile so we can report it with the result
                    # without creating a new object for each result. This will help if the
                    # consumer wants to re-create the tree.
                    profile_info = {
                        'id': profile['id'],
                        'title': profile.get('title', None),
                    }

                    for rule in self._list(profile['rules'], ListChecklistProfileRuleResultsException, 'rules'):
                        result = rule['result']

                        # "pass" and "not-applicable" aren't really findings... we may want a separate
                        # method to get all checklist results
                        if result == 'pass' or result == 'not-applicable':
                            continue

                        yield {
                            'checklist': checklist_info,
                            'profile': profile_info,
                            'result': rule
                        }


class CreateException(Exception):
    def __init__(self, kind, response):
        super(CreateException, self).__init__(
            f'could not create {kind}: {response}'
        )
        self.response = response


class ListException(Exception):
    def __init__(self, kind, response):
        super(ListException, self).__init__(
            f'*** WARNING: could not retrieve {kind}: {response}'
        )


class CreateSessionException(CreateException):
    def __init__(self, response):
        super(CreateSessionException, self).__init__('session', response)


class CreateScanException(CreateException):
    def __init__(self, response):
        super(CreateScanException, self).__init__('scan', response)


class ListScansException(ListException):
    def __init__(self, response):
        super(ListScansException, self).__init__('scans', response)


class ListMalwareException(ListException):
    def __init__(self, response):
        super(ListMalwareException, self).__init__(
            'malware', response
        )


class ListVulnerabilitiesException(ListException):
    def __init__(self, response):
        super(ListVulnerabilitiesException, self).__init__(
            'vulnerabilities', response
        )


class ListContentFindingsException(ListException):
    def __init__(self, response):
        super(ListContentFindingsException, self).__init__(
            'content findings', response
        )


class ListChecklistsException(ListException):
    def __init__(self, response):
        super(ListChecklistsException, self).__init__(
            'checklists', response
        )


class ListChecklistProfileRuleResultsException(ListException):
    def __init__(self, response):
        super(ListChecklistProfileRuleResultsException, self).__init__(
            'checklist profile rule results', response
        )
