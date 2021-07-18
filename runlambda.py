from mangum import Mangum
from sellout import app

lambda_handler = Mangum(app)
