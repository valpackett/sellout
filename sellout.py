import os
import typing
import functools
import mimetypes
from datetime import datetime, timedelta
from hashlib import sha256
from base64 import urlsafe_b64decode
from secrets import token_urlsafe
from urllib.parse import urlencode, urlparse
from dotenv import load_dotenv
from argon2 import PasswordHasher, exceptions as argonerr
from cryptography.hazmat.primitives import constant_time
from starlette.applications import Starlette
from starlette.requests import Request, HTTPConnection
from starlette.responses import Response, RedirectResponse, JSONResponse
from starlette.endpoints import HTTPEndpoint
from starlette.authentication import (
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
    UnauthenticatedUser,
    AuthCredentials,
    has_required_scope,
)
from starlette.routing import Route, Mount
from starlette.exceptions import HTTPException
from starlette.templating import Jinja2Templates
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.datastructures import Headers, MutableHeaders, FormData
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from aiodynamo.client import Client as DbClient
from aiodynamo.credentials import Credentials as DbCreds
from aiodynamo.errors import ItemNotFound
from aiodynamo.http.httpx import HTTPX
from httpx import AsyncClient

SCOPE_INFO = {
    "profile": "Get basic profile information",
    "email": "Get profile email address",
    "create": "Create new posts using Micropub",
    "update": "Edit existing posts using Micropub",
    "delete": "Delete posts using Micropub",
    "undelete": "Restore deleted posts using Micropub",
    "media": "Upload files using Micropub",
}
ALL_SCOPES = [k for k in SCOPE_INFO.keys()]
CSP_NOSCRIPT = "default-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
COMMON_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",  # kinda redundant with CSP but why not
    "Permissions-Policy": "sync-xhr=(), accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
}
DEFAULT_HEADERS = {**COMMON_HEADERS, "Content-Security-Policy": CSP_NOSCRIPT}

load_dotenv()
aws_region = os.environ["AWS_REGION"]
db_prefix = os.environ["DYNAMO_PREFIX"]
session_secret = os.environ["SESSION_SECRET"]
admin_pw_hash = os.environ["PASSWORD_HASH"]
hasher = PasswordHasher()
tpl = Jinja2Templates(directory="tpl")

mimetypes.add_type("font/woff2", ".woff2")


def db_table(h, tbl):
    return DbClient(HTTPX(h), DbCreds.auto(), aws_region).table(db_prefix + tbl)


# CloudFront -> API Gateway problems :/
class WeirdnessMiddleware(object):
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = MutableHeaders(scope=scope)
            xhost = headers.get("x-forwarded-host")
            xauth = headers.get("x-authorization")
            if xhost:
                headers["host"] = xhost
            if xauth:
                headers["authorization"] = xauth
        await self.app(scope, receive, send)


# https://github.com/encode/starlette/pull/920
def requires(
    scopes: typing.Union[str, typing.Sequence[str]],
    redirect: str = None,
) -> typing.Callable:
    scopes_list = [scopes] if isinstance(scopes, str) else list(scopes)

    def decorator(func: typing.Callable) -> typing.Callable:
        @functools.wraps(func)
        async def async_wrapper(*args: typing.Any, **kwargs: typing.Any) -> Response:
            request = kwargs.get("request", args[-1] if args else None)
            assert isinstance(request, Request)

            if redirect is None and not has_required_scope(request, ["auth"]):
                raise AuthenticationError(401, {"error": "unauthorized"})
            if not has_required_scope(request, scopes_list):
                if redirect is not None:
                    next_url = "{redirect_path}?{orig_request}".format(
                        redirect_path=request.url_for(redirect),
                        orig_request=urlencode({"next": str(request.url)}),
                    )
                    return RedirectResponse(url=next_url, status_code=303)
                raise AuthenticationError(403, {"error": "insufficient_scope"})
            return await func(*args, **kwargs)

        return async_wrapper

    return decorator


TOK_ERR = AuthenticationError(
    401, {"error": "unauthorized", "error_description": "Token is not valid"}
)


async def authenticate_bearer(request: Request, token: str):
    async with AsyncClient() as h:
        try:
            data = await db_table(h, "auth").get_item({"token": "B-" + token})
            if data.get("revoked") or data["host"] != request.headers["host"]:
                raise TOK_ERR
            request.scope["bearer_data"] = data
            return AuthCredentials(["auth", "via_bearer", *data["scopes"]]), SimpleUser(
                "admin"
            )
        except ItemNotFound:
            raise TOK_ERR


class TokenAndSessionBackend(AuthenticationBackend):
    async def authenticate(self, request: Request):
        if request.session.get("au", False):
            return AuthCredentials(["auth", "via_cookie", *ALL_SCOPES]), SimpleUser(
                "admin"
            )
        if "Authorization" in request.headers:
            try:
                scheme, token = request.headers["Authorization"].split()
                if scheme != "Bearer":
                    raise AuthenticationError(
                        400,
                        {
                            "error": "invalid_request",
                            "error_description": "Unsupported Authorization header scheme {}".format(
                                scheme
                            ),
                        },
                    )
                return await authenticate_bearer(request, token)
            except ValueError:
                raise AuthenticationError(
                    400,
                    {
                        "error": "invalid_request",
                        "error_description": "What even is this Authorization header?",
                    },
                )
        if request.method in ("POST", "PUT", "DELETE"):
            form = await request.form()
            if "access_token" in form:
                return await authenticate_bearer(request, form["access_token"])


class Login(HTTPEndpoint):
    async def get(self, request: Request):
        next = request.query_params.get("next", "/")
        if request.user.is_authenticated:
            return RedirectResponse(url=next, status_code=303)
        return tpl.TemplateResponse(
            "login.html",
            {"next": next, "request": request},
            headers=DEFAULT_HEADERS,
        )

    async def post(self, request: Request):
        form = await request.form()
        next = form.get("next", "/.sellout/")
        if request.user.is_authenticated:
            return RedirectResponse(url=next, status_code=303)
        error = "Something error??"
        try:
            if hasher.verify(admin_pw_hash, form.get("pw", "")):
                request.session["au"] = True
                return RedirectResponse(url=next, status_code=303)
        except argonerr.VerifyMismatchError as err:
            print(err)
            error = "The password did not match"
        except argonerr.VerificationError as err:
            print(err)
            error = "Something went wrong with the password check"
        return tpl.TemplateResponse(
            "login.html",
            {"next": next, "error": error, "request": request},
            headers=DEFAULT_HEADERS,
        )


def profile(request: Request):
    # TODO: actual profile
    return {"me": "https://{}/".format(request.headers["host"])}


async def redeem_auth_code(request: Request, form: FormData):
    if form.get("grant_type") != "authorization_code":
        raise AuthenticationError(400, {"error": "unsupported_grant_type"})
    if not "code" in form or not "client_id" in form or not "redirect_uri" in form:
        raise AuthenticationError(400, {"error": "invalid_request"})
    async with AsyncClient() as h:
        try:
            tbl = db_table(h, "auth")
            data = await tbl.get_item({"token": "C-" + form["code"]})
            time = datetime.fromisoformat(data["time"])
            if (
                datetime.utcnow() - time > timedelta(minutes=5)
                or form["client_id"] != data["client_id"]
                or form["redirect_uri"] != data["redirect_uri"]
                or data.get("used", False)
                or data["host"] != request.headers["host"]
            ):
                raise AuthenticationError(400, {"error": "invalid_grant"})
            if data.get("code_challenge_method") == "S256":
                if not "code_verifier" in form:
                    raise AuthenticationError(400, {"error": "invalid_request"})
                if not constant_time.bytes_eq(
                    sha256(form["code_verifier"].encode("ascii")).digest(),
                    urlsafe_b64decode(data["code_challenge"] + "=="),
                ):
                    # ^^ fun fact, we can always just add the padding: https://stackoverflow.com/a/49459036
                    raise AuthenticationError(400, {"error": "invalid_grant"})
            data["used"] = True
            await tbl.put_item(data)
            return data
        except (ItemNotFound, KeyError):
            raise AuthenticationError(400, {"error": "invalid_grant"})


def autherr(request, err):
    return tpl.TemplateResponse(
        "autherr.html",
        {
            "request": request,
            "err": err,
        },
        status_code=400,
        headers=DEFAULT_HEADERS,
    )


class Authorization(HTTPEndpoint):
    @requires("via_cookie", redirect="login")
    async def get(self, request: Request):
        if request.query_params.get("response_type") != "code":
            return autherr(request, "response_type MUST be 'code'")
        if not "client_id" in request.query_params:
            return autherr(request, "client_id MUST exist")
        if not "redirect_uri" in request.query_params:
            return autherr(request, "redirect_uri MUST exist")
        if not "state" in request.query_params:
            return autherr(request, "state MUST exist")
        client_id = None
        try:
            client_id = urlparse(request.query_params.get("client_id"))
        except ValueError:
            return autherr(request, "client_id MUST be a valid URL")
        redirect_uri = None
        try:
            redirect_uri = urlparse(request.query_params.get("redirect_uri"))
        except ValueError:
            return autherr(request, "redirect_uri MUST be a valid URL")
        if (
            client_id.scheme != redirect_uri.scheme
            or client_id.netloc != redirect_uri.netloc
        ):
            # TODO allow things linked by rel=redirect_uri
            return autherr(
                request,
                "redirect_uri MUST be on the same host as client_id (TODO: or an allowed one)",
            )
        req_scopes = request.query_params.get("scope", "profile").split()
        return tpl.TemplateResponse(
            "authorize.html",
            {
                "scope_info": SCOPE_INFO,
                "req_scopes": req_scopes,
                "request": request,
            },
            headers=DEFAULT_HEADERS,
        )

    async def post(self, request: Request):
        form = await request.form()
        await redeem_auth_code(request, form)
        return JSONResponse(profile(request))


class Token(HTTPEndpoint):
    @requires("via_bearer", redirect="login")
    async def get(self, request: Request):
        resp = profile(request)
        bd = request.scope["bearer_data"]
        resp["client_id"] = bd["client_id"]
        resp["scope"] = " ".join(bd["scopes"])
        return JSONResponse(resp)

    async def post(self, request: Request):
        form = await request.form()
        code_data = await redeem_auth_code(request, form)
        bearer = token_urlsafe(16)
        data = {
            "token": "B-" + bearer,
            "time": datetime.utcnow().isoformat(),
            "code_used": code_data["token"],
            "client_id": code_data["client_id"],
            "scopes": code_data["scopes"],
        }
        async with AsyncClient() as h:
            await db_table(h, "auth").put_item(data)
        resp = profile(request)
        resp["token_type"] = "Bearer"
        resp["access_token"] = bearer
        resp["scope"] = " ".join(data["scopes"])
        return JSONResponse(resp)


@requires("via_cookie", redirect="login")
async def allow(request: Request):
    if request.headers.get("sec-fetch-site", "same-origin") != "same-origin":
        return autherr(request, "request MUST be same-origin")
    form = await request.form()
    if not "client_id" in form:
        return autherr(request, "client_id MUST exist")
    if not "redirect_uri" in form:
        return autherr(request, "redirect_uri MUST exist")
    if not "state" in form:
        return autherr(request, "state MUST exist")
    scopes = [s for s in SCOPE_INFO.keys() if form.get("scope:" + s) == "on"]
    code = token_urlsafe(16)
    data = {
        "token": "C-" + code,
        "time": datetime.utcnow().isoformat(),
        "client_id": form["client_id"],
        "redirect_uri": form["redirect_uri"],
        "state": form["state"],
        "code_challenge": form.get("code_challenge"),
        "code_challenge_method": form.get("code_challenge_method"),
        "scopes": scopes,
        "host": request.headers["host"],
    }
    redir_sep = "?" if urlparse(form["redirect_uri"]).query == "" else "&"
    redir_qs = urlencode({"code": code, "state": form["state"]})
    redir_dest = form["redirect_uri"] + redir_sep + redir_qs
    async with AsyncClient() as h:
        await db_table(h, "auth").put_item(data)
    return RedirectResponse(url=redir_dest, status_code=303)


@requires("via_cookie", redirect="login")
async def logout(request: Request):
    del request.session["au"]
    return RedirectResponse(url="/", status_code=303)


@requires("via_cookie", redirect="login")
async def dashboard(request: Request):
    return tpl.TemplateResponse(
        "dashboard.html",
        {"request": request},
        headers=DEFAULT_HEADERS,
    )


async def testpage(request: Request):
    return tpl.TemplateResponse(
        "testpage.html",
        {"request": request},
        headers={
            "Link": '</.sellout/authz>; rel="authorization_endpoint", </.sellout/token>; rel="token_endpoint"',
            **DEFAULT_HEADERS,
        },
    )


def on_auth_error(conn: HTTPConnection, exc: AuthenticationError) -> Response:
    (status, obj) = exc.args
    return JSONResponse(obj, status_code=status)


async def on_auth_exception(request: Request, exc: AuthenticationError) -> Response:
    (status, obj) = exc.args
    return JSONResponse(obj, status_code=status)


app = Starlette(
    debug=True,
    routes=[
        Route("/", testpage),
        Route("/.sellout/", dashboard),
        Route("/.sellout/login", Login, name="login"),
        Route("/.sellout/authz", Authorization, name="authz"),
        Route("/.sellout/token", Token, name="token"),
        Route("/.sellout/allow", allow, name="allow", methods=["POST"]),
        Route("/.sellout/logout", logout, name="logout", methods=["POST"]),
        Mount("/.sellout/static", StaticFiles(directory="static"), name="static"),
    ],
    middleware=[
        Middleware(WeirdnessMiddleware),
        Middleware(
            SessionMiddleware,
            secret_key=session_secret,
            session_cookie="__Host-wheeeee",
            same_site="Lax",
            https_only=True,
        ),
        Middleware(
            AuthenticationMiddleware,
            backend=TokenAndSessionBackend(),
            on_error=on_auth_error,
        ),
    ],
    exception_handlers={AuthenticationError: on_auth_exception},
)
