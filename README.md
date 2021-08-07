# Sellout Engine

The "less indie" option for [IndieWeb]-powering a website.
Bezos is going to own every computer on the planet after all :D

- an [IndieAuth] server ([authorization-endpoint], [token-endpoint]) and [Micropub] implementation
- for GitHub-hosted static-generated sites
	- specifically for [Zola] ones, as only its TOML front-matter is supported
- designed to be able to run on AWS Lambda
- stores data like auth sessions in (oh no) DynamoDB
- **TODO** uploads media to S3 (of course) 
- should be put directly on the website's domain using a capable CDN
	- … like AWS CloudFront (yep)
	- with that, you can do cookie-authed Micropub for [micro-panel]

Oh and it has:

- hopefully good security
	- [`__Host-` prefixed, `Secure; HttpOnly; SameSite` cookie](https://scotthelme.co.uk/tough-cookies/) for sessions
	- [`Sec-Fetch-Site`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site) checks to be extra sure form submissions aren't cross-site
	- very strict `Content-Security-Policy` and other fun headers
	- PKCE in IndieAuth
	- hopefully no logic flaws??
- definitely good visual design
- not a lot of code
- very cool and modern, async and typed Python code

[IndieWeb]: https://indieweb.org/
[IndieAuth]: https://indieweb.org/IndieAuth
[authorization-endpoint]: https://indieweb.org/authorization-endpoint
[token-endpoint]: https://indieweb.org/token-endpoint
[Micropub]: https://indieweb.org/micropub
[Zola]: https://www.getzola.org/
[micro-panel]: https://github.com/unrelentingtech/micro-panel

## Configuration

Unfortunately, I don't really have the energy and motivation to fully document everything.
Or automate deployment via tools like CloudFormation/SAM, etc.
But here's an attempt at *some* documentation.

### DynamoDB

Create tables with a common prefix like `yourwebsite-`, I'll use `unrelentingtech-`:

- `unrelentingtech-auth` with partition key `token`

### AWS Systems Manager Parameter Store

Store secrets here.
Add SecureString parameters with a common prefix e.g. `/sellout`:

- `/sellout/GITHUB_TOKEN`: a Personal Access Token for a bot account that just has access to the site repo
- `/sellout/PASSWORD_HASH`: argon2 hash of the admin password
- `/sellout/SESSION_SECRET`: some big random string

### Lambda

I deploy the Lambda from GitHub Actions here.
I guess you can do that in a fork too?

Python 3.8 runtime, `runlambda.lambda_handler` handler.

Set a reasonable amount of memory (256-512MB) and timeout (1 min).

Environment variables:

- `PYTHONPATH`: `/var/task/__pypackages__/3.8/lib:/var/runtime`
- `SSM_PREFIX`: as above e.g. `/sellout`
- `DYNAMO_PREFIX`: as above e.g. `unrelentingtech-`
- `GITHUB_REPO`: user and repo e.g. `unrelentingtech/site`
- `GITHUB_BRANCH`: e.g. `main`

### IAM

Ah, who doesn't love this. Cloud Engineering time!
Basically we need the Lambda to have access to SSM parameters and the key for them, DynamoDB and S3.
There's also some log stuff that was auto generated.

Note the table and parameter prefixes.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:eu-west-1:REDACTED:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:eu-west-1:REDACTED:log-group:/aws/lambda/sellout-unrelentingtech:*"
            ]
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter*",
                "dynamodb:BatchWriteItem",
                "dynamodb:UpdateTimeToLive",
                "kms:Decrypt",
                "dynamodb:PutItem",
                "dynamodb:DescribeTable",
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:Scan",
                "dynamodb:Query",
                "dynamodb:UpdateItem"
            ],
            "Resource": [
                "arn:aws:dynamodb:eu-west-1:REDACTED:table/unrelentingtech-*",
                "arn:aws:kms:*:*:key/alias/aws/ssm",
                "arn:aws:ssm:*:*:parameter/sellout/*"
            ]
        },
        {
            "Sid": "VisualEditor2",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:AbortMultipartUpload",
                "s3:PutObjectAcl"
            ],
            "Resource": "arn:aws:s3:::unrelentingtech/*"
        }
    ]
}
```

### API Gateway

Typical `/{proxy+}`-all-the-things config, set `*/*` for Binary Media Types in API Settings (!).

### CloudFront

Unfortunately CloudFront is really weird about some headers, so we have to use CloudFront Functions to rename them :/
These are handled in `WeirdnessMiddleware`, which **MUST be removed if not using this CDN setup**!

Setup a behavior to forward requests to the Lambda:
- path pattern `.sellout*`
- the something.api-gateway… origin
- cache policy: CachingDisabled (probably can cache, but there's like, no need to)
- origin request policy: custom
	- headers: Origin, Accept-Charset, Accept, x-authorization, x-forwarded-host, Referer, Accept-Language
	- cookies: all
	- query strings: all
- viewer request function:

```js
function handler(event) {
    var req = event.request
    req.headers['x-forwarded-host'] = { value: req.headers['host'].value }
    if (req.headers['authorization'])
        req.headers['x-authorization'] = { value: req.headers['authorization'].value }
    return req
}
```

And with all that, `https://your.example.com/.sellout/login` should hopefully work :)

Now add links to your actual content pages, e.g. also with CF Functions:

```js
  resp.headers['link'] = { value: '</.sellout/authz>; rel="authorization_endpoint", </.sellout/token>; rel="token_endpoint", </.sellout/pub>; rel="micropub"' }
```

Also why not e.g. enforce some security for your logged in self, while allowing [more open access](https://enable-cors.org/) for the public:

```js
  var csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src data: https: 'self'; media-src https: 'self'; script-src 'self'; object-src 'none'; base-uri 'none'"
  if (req.cookies['__Host-wheeeee']) {
    csp += "; frame-ancestors 'none'"
    resp.headers['cross-origin-opener-policy'] = { value: "same-origin" }
  } else {
    csp += "; frame-ancestors https:"
    resp.headers['access-control-allow-origin'] = { value: "*" }
  }
  resp.headers['content-security-policy'] = { value: csp }
```

(include the `__Host-wheeeee` cookie in the cache policy for the website content!)

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](https://unlicense.org).

(Note: different licenses apply to dependencies.)
