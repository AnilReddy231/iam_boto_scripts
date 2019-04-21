'''
This script will traverse through all the users and keys creation date, last used date and notifies the subscribers of
the topic about the actions that were been taken as part of the run.  manage_access_keys.json has the required policy
information which is required to allow the user to upload the keys to S3 Bucket.
'''

import boto3
import logging
import os, csv, dateutil
from botocore.exceptions import ClientError
from datetime import timedelta, date, datetime
from time import sleep
from collections import defaultdict
import pdb

# Setup logging
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)


DAYS = 90
GRACE_PERIOD = 15

SUMMARY = ""
BUCKET_NAME = "access-keys-xxxxx"
ACTION_TOPIC_ARN = "arn:aws:sns:us-east-1:xxxxxxx:iam_keys_rotation"


def check_user_keys(client):
    '''
    Checks IAM Users keys alone
    '''
    global SUMMARY
    max_age = client.get_account_password_policy()['PasswordPolicy']['MaxPasswordAge']
    credential_report = get_credential_report(client)

    for row in credential_report:
        if row['password_enabled'] != "true":
            continue  # Skip IAM Users without passwords, they are service accounts

        password_expires = days_left(row['password_last_changed'], max_age)
        if password_expires <= 0:
            SUMMARY = SUMMARY + f"\n{row['user']}'s Password expired {password_expires * -1} days ago"
        elif password_expires < GRACE_PERIOD:
            SUMMARY = SUMMARY + f"\n{row['user']}'s Password Will expire in {password_expires} days"


def get_credential_report(client):
    '''
    Generates credential report for all the users who have console access
    '''
    report = client.generate_credential_report()
    if report['State'] == 'COMPLETE':
        try:
            response = client.get_credential_report()
            credential_report_csv = response['Content'].decode('utf-8')
            reader = csv.DictReader(credential_report_csv.splitlines())
            credential_report = []
            for row in reader:
                credential_report.append(row)
            return credential_report
        except ClientError as e:
            print("Unknown error getting Report: " + e.message)
    else:
        sleep(2)
        return get_credential_report(client)


def days_left(last_changed, period):
    ''' returns how many days left for expiry of the keys, a negative value will be returned if already expired '''
    if type(last_changed) is str:
        last_changed_date = dateutil.parser.parse(last_changed).date()
    else:
        last_changed_date = last_changed.date()
    delta = (last_changed_date + timedelta(period)) - date.today()
    return delta.days


def check_access_keys(client,age_threshold,use_threshold):
    ''' Checks access keys of each user and marks thier status based on their creation date and recent usage '''
    logging.info('Checking Access keys...')
    keyList = []
    users = [user['UserName'] for user in client.list_users()['Users']]
    # Get all users
    for user in users:
        keys_metadata = client.list_access_keys(UserName=user)['AccessKeyMetadata']

        # Set a username for the tempDict
        # Check if user has a key
        if keys_metadata:
            for key in keys_metadata:
                userDict = defaultdict(lambda: False)
                userDict['Username'] = user
                userDict['AccessKeyId'] = key['AccessKeyId']
                userDict['Status'] = key['Status']
                userDict['CreateDate'] = key['CreateDate']
                key_expires = days_left(key['CreateDate'], age_threshold)

                if key_expires <= 0:
                    userDict['Expired'] = True
                elif key_expires < use_threshold:
                    userDict['About_To_Expire'] = True
                userDict['Unused'] = is_being_used(client,key['AccessKeyId'],use_threshold)
                keyList.append(userDict)
    return keyList


def is_being_used(client, KeyId, use_threshold):
    ''' Checks when the access was last used '''
    response = client.get_access_key_last_used(AccessKeyId=KeyId)
    last_used = response['AccessKeyLastUsed']
    if last_used['ServiceName'] == 'N/A':
        return True
    else:
        lastUsedDate = last_used['LastUsedDate'].strftime('%Y-%m-%dT%H:%M:%S+00:00')

        key_unused = days_left(lastUsedDate, use_threshold)
        if key_unused <=0:
            return True
        else:
            return False


def deactivate_key(client,username,access_key_id):
    ''' DeActivates the key if if its expired'''
    try:
        client.update_access_key(UserName=username, AccessKeyId=access_key_id, Status="Inactive")
        return True
    except Exception as e:
        print("type error: " + str(e))
        return False


def generate_new_key(client,username):
    ''' Generates new keys before DeActivating the expired keys, It might fail to create a new one if user has already 2 keys in place '''
    s3 = boto3.resource('s3')
    try:
        response = client.create_access_key(UserName=username)['AccessKey']
        header = ['AccessKeyId', 'SecretAccessKey']
        data = {key: value for key, value in response.items() if key in header}
        key = response['AccessKeyId']
        with open('temp.csv', 'w') as creds:
            writer = csv.DictWriter(creds, header)
            writer.writeheader()
            writer.writerow(data)
        s3.Object(BUCKET_NAME, f'{key}.csv').upload_file('temp.csv')
        os.remove('temp.csv')
        return key
    except Exception as e:
        print("type error: " + str(e))


def delete_access_key(client,username,access_key_id):
    ''' Keys which were Deactivated in the last run will be deleted upon your confirmation'''
    try:
        client.delete_access_key(UserName=username, AccessKeyId=access_key_id)
        return True
    except Exception as e:
        print("type error: " + str(e))
        return False


def send_completion_email():
    '''Action Summary of the current run will be mailed to the subscribers of the topic in SNS'''
    global SUMMARY
    client = boto3.client('sns')
    message = "The following Actions were taken by the Expire Users Script at {}: ".format(datetime.now()) + SUMMARY
    response = client.publish(
            TopicArn=ACTION_TOPIC_ARN,
            Message=message,
            Subject="Expire Users Report for {}".format(date.today())
        )


def main():
    global SUMMARY
    client = boto3.client("iam")
    check_user_keys(client)
    # Get all users with keys and check if they've expired
    keyList = check_access_keys(client,DAYS,GRACE_PERIOD)

    for curr_key in keyList:
        Username = curr_key['Username']
        AccessKeyId = curr_key['AccessKeyId']
        if curr_key['Status'] == "Inactive":
            proceed=input(f"\n User's {Username} key:{AccessKeyId} is InActive. Would you like it to be deleted: (Y/N)")
            if proceed.lower() == 'y' or proceed.lower() == 'yes':
                if delete_access_key(client,Username,AccessKeyId):
                    SUMMARY = SUMMARY + f"\n The Access Key {AccessKeyId} belonging to User {Username} had been deleted"

        elif curr_key['Expired']:
            print(f"\n User's:{Username} key:{AccessKeyId} got expired")
            new_key = generate_new_key(client, curr_key['Username'])
            if new_key is not None:
                SUMMARY = SUMMARY + f"\n Generated new key: {new_key} for user: {Username}. Credentials can be found at: {BUCKET_NAME}/{new_key}.csv"
            if deactivate_key(client,Username,AccessKeyId):
                SUMMARY = SUMMARY + f'\n The Access Key {AccessKeyId} belonging to User {Username} has been automatically deactivated since it is {DAYS} days old'
        elif curr_key['Unused']:
            SUMMARY = SUMMARY + f"\n User's:{Username} key:{AccessKeyId} hadn\'t been used yet (or)  in last {GRACE_PERIOD} days."

    if SUMMARY:
        send_completion_email()


if __name__ == '__main__':
    main()