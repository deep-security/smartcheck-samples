# list-vulnerabilities

[![License](https://img.shields.io/badge/License-Apache%202-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This module shows how to use the Deep Security Smart Check API to retrieve the vulnerability findings from the last scan on an image.

See the [API reference documentation](https://deep-security.github.io/smartcheck-docs/api/) for more things you can do with the Deep Security Smart Check API.

## Get started

### Install dependencies

You will need Python 3 and [pipenv](https://github.com/pypa/pipenv) to install the dependencies for this project.

```sh
$ pipenv install
Installing dependencies from Pipfile.lock (c53762)…
  🐍   ▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉ 2/2 — 00:00:00
To activate this project's virtualenv, run the following:
 $ pipenv shell
```

### Usage

```text
usage: list-vulnerabilities.py [-h] [--smartcheck-host SMARTCHECK_HOST]
                               [--smartcheck-user SMARTCHECK_USER]
                               [--smartcheck-password SMARTCHECK_PASSWORD]
                               [--insecure-skip-tls-verify]
                               [--min-severity MIN_SEVERITY]
                               [--show-overridden] [--show-fixed]
                               image

List vulnerabilities found in scans

positional arguments:
  image                 The image to scan. Example:
                        registry.example.com/project/image:latest

optional arguments:
  -h, --help            show this help message and exit
  --smartcheck-host SMARTCHECK_HOST
                        The hostname of the Deep Security Smart Check
                        deployment. Example: smartcheck.example.com
  --smartcheck-user SMARTCHECK_USER
                        The userid for connecting to Deep Security Smart Check
  --smartcheck-password SMARTCHECK_PASSWORD
                        The password for connecting to Deep Security Smart
                        Check
  --insecure-skip-tls-verify
                        Ignore certificate errors when connecting to Deep
                        Security Smart Check
  --min-severity MIN_SEVERITY
                        The minimum severity of vulnerability to show.
                        Defaults to "high". Values:
                        [defcon1,critical,high,medium,low,negligible,unknown]
  --show-overridden     Show vulnerabilities that have been marked as
                        overridden
  --show-fixed          Show vulnerabilities that have been fixed by a later
                        layer
```

## API flow

1. Start out by creating a session and getting the session token. We'll use a sample user with a not-very-complex password:

   <details open>
     <summary>"Create session" request</summary>

   ```text
   POST /api/sessions HTTP/1.1
   Content-Type: application/json
   X-Api-Version: 2018-05-01
   Accept: application/json

   { "user": { "userid": "scan-user", "password": "test" } }
   ```

   </details>

   <details open>
     <summary>"Create session" response</summary>

   ```text
   HTTP/1.1 201 Created
   Content-Type: application/json

   {
     ...
     "token": "bmljZSB0cnkK",
     "href": "{session_href}",
     ...
   }
   ```

   </details>

   We'll keep the `href` and `token` for later use.

2. Then we'll ask for the most recent scan that matches the image details:

   <details open>
     <summary>"List scans" request</summary>

   ```text
   GET /api/scans?registry=registry.example.com&repository=fake-image&tag=latest&exact=true&limit=1 HTTP/1.1
   X-Api-Version: 2018-05-01
   Authorization: Bearer bmljZSB0cnkK
   Accept: application/json
   ```

   </details>

   <details open>
     <summary>"List scans" response</summary>

   ```text
   HTTP/1.1 200 OK
   Content-Type: application/json
   Link: <{next_href}>;rel="next"

   {
     "scans": [ {
       ...
       "details": {
         ...
         "results": [ {
           ...
           "vulnerabilities": "{href}",
           ...
         } ]
       }
     } ],
     "next": "dGhpcyBpcyBhIGN1cnNvciBmb3Igc2NhbnMK"
   }
   ```

   </details>

3. We'll dig around in the scan details to get the layer vulnerabilities URL and then:

   <details open>
     <summary>"List scan layer vulnerabilities" request</summary>

   ```text
   GET {href} HTTP/1.1
   Authorization: Bearer bmljZSB0cnkK
   X-Api-Version: 2018-05-01
   Accept: application/json
   ```

   </details>

   <details open>
     <summary>"List scan layer vulnerabilities" response</summary>

   ```text
   HTTP/1.1 200 OK
   Content-Type: application/json
   Link: <{next_href}>;rel="next"

   {
     "vulnerabilities": [ ... ],
     "next": "dGhpcyBpcyBhIGN1cnNvciBmb3IgdnVsbnMK"
   }
   ```

   </details>

4. We'll process the first page of vulnerabilities, then we'll check if the `Link rel="next"` header exists, and it does, so we'll use it to get the next page of results:

   <details open>
     <summary>"List scan layer vulnerabilities" request #2</summary>

   ```text
   GET {next_href} HTTP/1.1
   Authorization: Bearer bmljZSB0cnkK
   X-Api-Version: 2018-05-01
   Accept: application/json
   ```

   </details>

   <details open>
     <summary>"List scan layer vulnerabilities" response #2</summary>

   ```text
   HTTP/1.1 200 OK
   Content-Type: application/json

   {
     "vulnerabilities": [ ... ]
   }
   ```

   </details>

5. We'll process the page of vulnerabilities that we got back, and look to see if there's a `Link rel="next"` header, and there is not, so we'll go back to step 3 to find the next layer with vulnerabilities in it.

6. When we're done with layers, we'll practice good hygiene and terminate our session:

   <details open>
     <summary>"Delete session" request</summary>

   ```text
   DELETE {session_href} HTTP/1.1
   Authorization: bmljZSB0cnkK
   ```

   </details>

   <details open>
     <summary>"Delete session" response</summary>

   ```text
   HTTP/1.1 204 No Content
   ```

   </details>

Done!
