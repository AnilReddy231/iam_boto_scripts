import boto3, json
import logging, sys
import argparse


def get_policy(Name, Arn, Id):
    client = boto3.client ('iam')
    body = client.get_policy_version (PolicyArn=Arn, VersionId=Id)
    logging.info(f"Printing body for policy: {Name} in the JSON Format {json.dumps (body['PolicyVersion']['Document'], indent=2)}")


def orphan_policy(delete, policy_names):
    iam_client = boto3.client (
        'iam'
    )

    iam_policies = iam_client.list_policies (Scope='Local', MaxItems=1000)['Policies']
    orphans = list ()
    for policy in iam_policies:
        if policy['AttachmentCount'] == 0:
            orphans.append (policy)

    for policy in orphans:

        if policy_names:
            delete_policies = policy_names
        else:
            delete_policies = [plc['PolicyName'] for plc in orphans]

        if policy['PolicyName'] in delete_policies:
            get_policy(policy['PolicyName'], policy['Arn'], policy['DefaultVersionId'])
            if delete is True:
                logging.info (f"Proceeding on to deleting the policy: {policy['PolicyName']}")
                # You must delete all the non-default policy's versions
                non_default = [ version for version in iam_client.list_policy_versions(PolicyArn=policy['Arn'])['Versions'] if version['IsDefaultVersion'] is False]
                for version in non_default:
                    iam_client.delete_policy_version(PolicyArn=policy['Arn'], VersionId=version['VersionId'])
                # Delete policy  will delete the policy's default version
                iam_client.delete_policy(PolicyArn=policy['Arn'])


def arg_parse(*args, **kwargs):
    parser = argparse.ArgumentParser(
        description=f"Program to Describe and Delete the required or All Orphan Custom IAM policies.",
        prog=sys.argv[0],
    )

    switch_group = parser.add_mutually_exclusive_group (required=True)

    switch_group.add_argument (
        "-S", "--describe",
        action='store_true',
        help="Dumps All or Requested Orphan IAM Policies",
    )

    switch_group.add_argument (
        "-D", "--delete",
        action='store_true',
        help="Deletes All or Requested Orphan IAM Policies",
    )

    parser.add_argument(
        "-p", "--policy_names",
        nargs = "*",
        type = str,  # any type/callable can be used here
        default = [],
        action = 'store',
        help = "List of Orphan IAM Policies to Act on, Else All Orphan IAM Policies",
    )

    parsed = parser.parse_args ()

    orphan_policy(parsed.delete, parsed.policy_names)


if __name__ == '__main__':
    logging.basicConfig (format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)
    sys.exit (arg_parse (*sys.argv))
