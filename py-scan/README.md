# scan

[![License](https://img.shields.io/badge/License-Apache%202-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This module shows how to use the Deep Security Smart Check API to start a scan and wait for the results.

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
scan.py [-h]
        [--smartcheck-host SMARTCHECK_HOST]
        [--smartcheck-user SMARTCHECK_USER]
        [--smartcheck-password SMARTCHECK_PASSWORD]
        [--insecure-skip-tls-verify]
        [--image-pull-auth IMAGE_PULL_AUTH]
        [--registry-root-cas REGISTRY_ROOT_CAS]
        [--insecure-skip-registry-tls-verify]
        [--no-wait]
        image

Start a scan

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
  --image-pull-auth IMAGE_PULL_AUTH
                        A JSON object of credentials for authenticating with
                        the registry to pull the image from
  --registry-root-cas REGISTRY_ROOT_CAS
                        A file containing the root CAs (in PEM format) to
                        trust when connecting to the registry
  --insecure-skip-registry-tls-verify
                        Ignore certificate errors from the image registry
  --no-wait             Exit after requesting the scan
```

### Provide image pull credentials

Use the `--image-pull-auth` parameter to provide credentials for pulling the image from the registry where it is stored. This parameter is a string containing a JSON object with the same structure as the `source.credentials` object in the [`createScan` API operation](https://deep-security.github.io/smartcheck-docs/api/#operation/createScan):

#### Username + password

To authenticate using a username + password:

```json
{
  "username": "username",
  "password": "************"
}
```

#### Token

To authenticate using a token:

```json
{
  "token": "bmljZSB0cnkK"
}
```

#### AWS

To authenticate using an AWS access key ID and secret access key:

```json
{
  "aws": {
    "region": "us-east-1",
    "accessKeyID": "AKIAIOSFODNN7EXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

To authenticate using an AWS access key ID and secret access key to assume a role and access a registry in another account:

```json
{
  "aws": {
    "region": "us-east-1",
    "accessKeyID": "AKIAIOSFODNN7EXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "role": "arn:aws:iam::account-id:role/role-name",
    "externalID": "myExternalID",
    "roleSessionName": "DeepSecuritySmartCheck",
    "registry": "account-id"
  }
}
```
