import os
import typing
import functools
from urllib.parse import urlencode
from dotenv import load_dotenv
from argon2 import PasswordHasher, exceptions as argonerr
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
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
from mangum import Mangum

load_dotenv()
session_secret = os.environ["SESSION_SECRET"]
admin_pw_hash = os.environ["PASSWORD_HASH"]
hasher = PasswordHasher()
tpl = Jinja2Templates(directory="tpl")

# https://github.com/encode/starlette/pull/920
def requires(
    scopes: typing.Union[str, typing.Sequence[str]],
    status_code: int = 403,
    redirect: str = None,
) -> typing.Callable:
    scopes_list = [scopes] if isinstance(scopes, str) else list(scopes)

    def decorator(func: typing.Callable) -> typing.Callable:
        @functools.wraps(func)
        async def async_wrapper(*args: typing.Any, **kwargs: typing.Any) -> Response:
            request = kwargs.get("request", args[0] if args else None)
            assert isinstance(request, Request)

            if not has_required_scope(request, scopes_list):
                if redirect is not None:
                    next_url = "{redirect_path}?{orig_request}".format(
                        redirect_path=request.url_for(redirect),
                        orig_request=urlencode({"next": str(request.url)}),
                    )
                    return RedirectResponse(url=next_url, status_code=303)
                raise HTTPException(status_code=status_code)
            return await func(*args, **kwargs)

        return async_wrapper

    return decorator


class TokenAndSessionBackend(AuthenticationBackend):
    async def authenticate(self, request):
        if "Authorization" in request.headers:
            try:
                scheme, token = request.headers["Authorization"].split()
                if scheme != "Bearer":
                    raise AuthenticationError(
                        "Unsupported Authorization header scheme {}".format(scheme)
                    )
                # TODO
            except ValueError:
                raise AuthenticationError("What even is this Authorization header?")
        if request.session.get("au", False):
            return AuthCredentials(["via_cookie"]), SimpleUser("admin")


class Login(HTTPEndpoint):
    async def get(self, request: Request):
        next = request.query_params.get("next", "/")
        if request.user.is_authenticated:
            return RedirectResponse(url=next, status_code=303)
        return tpl.TemplateResponse(
            "login.html",
            {"noscript": True, "next": next, "request": request},
        )

    async def post(self, request: Request):
        form = await request.form()
        next = form.get("next", "/")
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
            {"noscript": True, "next": next, "error": error, "request": request},
        )


@requires("via_cookie", redirect="login")
async def logout(request: Request):
    del request.session["au"]
    return RedirectResponse(url="/", status_code=303)


@requires("via_cookie", redirect="login")
async def dashboard(request: Request):
    return tpl.TemplateResponse(
        "dashboard.html",
        {"noscript": True, "request": request},
    )


app = Starlette(
    debug=True,
    routes=[
        Route("/", dashboard),
        Route("/login", Login, name="login"),
        Route("/logout", logout, name="logout", methods=["POST"]),
        Mount("/static", StaticFiles(directory="static"), name="static"),
    ],
    middleware=[
        Middleware(
            SessionMiddleware,
            secret_key=session_secret,
            session_cookie="__Host-wheeeee",
            same_site="strict",
            https_only=True,
        ),
        Middleware(AuthenticationMiddleware, backend=TokenAndSessionBackend()),
    ],
)
lambda_handler = Mangum(app)
