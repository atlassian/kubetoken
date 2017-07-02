# kubetoken

[![Build Status](https://travis-ci.org/atlassian/kubetoken.svg?branch=master)](https://travis-ci.org/atlassian/kubetoken)

## Synopsis

`kubetoken` issues temporary certificates for access to Kubernetes clusters.

## Installation

Installation is covered in a [seperate document](INSTALLTION.md).

## Deployment

Deploying kubetoken involves two steps.

1. deploying kubetokend as a kubernetes service
2. distributing the kubetoken cli tool.

### Contributing

Pull requests, issues and comments welcome. For pull requests:

* _Do not_ submit a pull request without an accompanying issue. All pull requests _must_ include an `Updates` or `Fixes` line.
* Add tests for new features and bug fixes.
* Follow the existing style.
* Separate unrelated changes into multiple pull requests.

See the existing issues for things to start contributing.

For bigger changes, make sure you start a discussion first by creating an issue and explaining the intended change.

Atlassian requires contributors to sign a Contributor License Agreement, known as a CLA. This serves as a record
stating that the contributor is entitled to contribute the code/documentation/translation to the project and is willing
to have it used in distributions and derivative works (or is willing to transfer ownership).

Prior to accepting your contributions we ask that you please follow the appropriate link below to digitally sign the
CLA. The Corporate CLA is for those who are contributing as a member of an organization and the individual CLA is for
those contributing as an individual.

* [CLA for corporate contributors](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=e1c17c66-ca4d-4aab-a953-2c231af4a20b)
* [CLA for individuals](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d)

# License

Copyright (c) 2017 Atlassian and others. MIT licensed, see LICENSE file.
