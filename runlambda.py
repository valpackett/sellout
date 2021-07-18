import os
import boto3

ssm = boto3.client("ssm")
ssm_prefix = os.environ["SSM_PREFIX"]
os.environ["SESSION_SECRET"] = ssm.get_parameter(
    Name=ssm_prefix + "/sessionsecret", WithDecryption=True
)["Parameter"]["Value"]
os.environ["PASSWORD_HASH"] = ssm.get_parameter(
    Name=ssm_prefix + "/passwordhash", WithDecryption=True
)["Parameter"]["Value"]

from mangum import Mangum
from sellout import app

lambda_handler = Mangum(app)
