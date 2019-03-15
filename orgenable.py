import boto3
import json
import sys
import traceback
import logging.handlers
# Logging Settings
logging.basicConfig(stream=sys.stderr)  # , level=logging.INFO)
logger = logging.getLogger('enableawsorganizations')
logger.setLevel(logging.INFO)


AWSCREDPROFILENAME = ""  # Set this to your aws profile name that can assume a role into all child acccounts
ORG_ROLE_NAME_TO_ASSUME = ""  # Set this to the name of the role that can be assume in all of the child accounts


# Establish creds from aws local profile
session = boto3.Session(profile_name=AWSCREDPROFILENAME)
org_sts = session.client('sts')
root_org_client = session.client('organizations')


# Create client with role to child accounts accounts
def remote_client(account, client):
    try:
        role = org_sts.assume_role(RoleArn="arn:aws:iam::" + account + ":role/" + ORG_ROLE_NAME_TO_ASSUME, DurationSeconds=900, RoleSessionName='enableawsorganizations')
        return boto3.client(client,
                            aws_access_key_id=role['Credentials']['AccessKeyId'],
                            aws_secret_access_key=role['Credentials']['SecretAccessKey'],
                            aws_session_token=role['Credentials']['SessionToken'])
    except Exception as e:
        if not isinstance(e, KeyError) and e.response['Error']['Code'] == 'AccessDenied':
            logger.error('Access Denied to account ' + account)
            return True
        else:
            logger.error(traceback.format_exc())


# Find all accounts missing the service linked role
token = 'NextToken'
resource_Name = 'Handshakes'
resource_role = root_org_client.list_handshakes_for_organization(Filter={'ActionType': 'ADD_ORGANIZATIONS_SERVICE_LINKED_ROLE'})
while token in resource_role:
    r = root_org_client.list_handshakes_for_organization(Filter={'ActionType': 'ADD_ORGANIZATIONS_SERVICE_LINKED_ROLE'}, NextToken=resource_role[token])
    resource_role[resource_Name] = resource_role[resource_Name] + r[resource_Name]
    if token in r:
        resource_role[token] = r[token]
    else:
        resource_role.pop(token, None)

logger.debug(json.dumps(resource_role, sort_keys=True, indent=4, default=str, separators=(',', ': ')))


for r in resource_role['Handshakes']:
    for a in r['Resources']:
        if a['Type'] == 'ACCOUNT':
            account = a['Value']
            break
    try:
        accept_client = remote_client(account=account, client='organizations')
        if isinstance(accept_client, bool) and accept_client:
            continue
        a_response = accept_client.accept_handshake(HandshakeId=r['Id'])
        if a_response and 'Handshake' in a_response:
            if a_response['Handshake']['State'] == 'ACCEPTED':
                logger.info(account + ' Accepted Handshake')
            else:
                logger.warning(json.dumps(a_response, sort_keys=True, indent=4, default=str, separators=(',', ': ')))
    except Exception as e:
        if not isinstance(e, KeyError) and e.response['Error']['Code'] == 'HandshakeAlreadyInStateException':
            logger.warning('Already Accepted ' + account)
        else:
            logger.error(traceback.format_exc())


# # Find all accounts that need to approve all features
token = 'NextToken'
resource_Name = 'Handshakes'
resource = root_org_client.list_handshakes_for_organization(Filter={'ActionType': 'APPROVE_ALL_FEATURES'})
while token in resource:
    r = root_org_client.list_handshakes_for_organization(Filter={'ActionType': 'APPROVE_ALL_FEATURES'}, NextToken=resource[token])
    resource[resource_Name] = resource[resource_Name] + r[resource_Name]
    if token in r:
        resource[token] = r[token]
    else:
        resource.pop(token, None)


for r in resource['Handshakes']:

    for a in r['Resources']:
        if a['Type'] == 'ACCOUNT':
            account = a['Value']
            break

    if r['State'] == 'OPEN':
        try:
            accept_client = remote_client(account=account, client='organizations')
            if isinstance(accept_client, bool) and accept_client:
                continue
            a_response = accept_client.accept_handshake(HandshakeId=r['Id'])
            if a_response and 'Handshake' in a_response:
                if a_response['Handshake']['State'] == 'ACCEPTED':
                    logger.info(account + ' Accepted Handshake')
                else:
                    logger.warning(json.dumps(a_response, sort_keys=True, indent=4, default=str, separators=(',', ': ')))
        except Exception as e:
            if not isinstance(e, KeyError) and e.response['Error']['Code'] == 'HandshakeAlreadyInStateException':
                logger.warning('Already Accepted ' + account)
            else:
                logger.error(traceback.format_exc())
