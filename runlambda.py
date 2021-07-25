import os
import boto3

ssm = boto3.client("ssm")
for var in ["SESSION_SECRET", "PASSWORD_HASH", "GITHUB_TOKEN"]:
    os.environ[var] = ssm.get_parameter(
        Name=os.environ["SSM_PREFIX"] + "/" + var, WithDecryption=True
    )["Parameter"]["Value"]

from mangum import Mangum
from sellout import app

lambda_handler = Mangum(app)
