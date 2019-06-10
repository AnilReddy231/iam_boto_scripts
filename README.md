# IAM Boto3 Scripts
Python boto3 scripts related AWS IAM

## IAM Access Keys Rotation

__iam_keys_rotation.py__ - This script will traverse through all the users and keys creation date, last used date and notifies the subscribers of
the topic about the actions that were been taken as part of the run.  

manage_access_keys.json has the required policy
information which is required to allow the user to upload the keys to S3 Bucket.


__orphan_iam_policy.py__ - Program to Describe and Delete the required or All Orphan Custom IAM policies.
```shell

usage: orphan_iam_policy.py [-h] (-S | -D)
                            [-p [POLICY_NAMES [POLICY_NAMES ...]]]

Program to Describe and Delete the required or All Orphan Custom IAM policies.

optional arguments:
  -h, --help            show this help message and exit
  -S, --describe        Dumps All or Requested Orphan IAM Policies
  -D, --delete          Deletes All or Requested Orphan IAM Policies
  -p [POLICY_NAMES [POLICY_NAMES ...]], --policy_names [POLICY_NAMES [POLICY_NAMES ...]]
                        List of Orphan IAM Policies to Act on, Else All Orphan
                        IAM Policies

```