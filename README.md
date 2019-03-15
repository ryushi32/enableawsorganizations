# Enable AWS Organizations using a cross account role
Python Script to automate the acceptance from all child AWS accounts using a cross account role that can be assumed by a local AWS profile either STS assume role with SAML or a local api key pair.

Script will create all missing cross account trust's.
Script will then accept the request on all of the child accounts behalf.
