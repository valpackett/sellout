import os
from dotenv import load_dotenv
from argon2 import PasswordHasher, exceptions as argonerr
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse
from starlette.endpoints import HTTPEndpoint
from starlette.authentication import (
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
    UnauthenticatedUser,
    AuthCredentials,
    requires,
)
from starlette.routing import Route, Mount
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
        redir = request.query_params.get("redir", "/")
        if request.user.is_authenticated:
            return RedirectResponse(url=redir, status_code=303)
        return tpl.TemplateResponse(
            "login.html",
            {"noscript": True, "redir": redir, "request": request},
        )

    async def post(self, request: Request):
        form = await request.form()
        redir = form.get("redir", "/")
        if request.user.is_authenticated:
            return RedirectResponse(url=redir, status_code=303)
        error = "Something error??"
        try:
            if hasher.verify(admin_pw_hash, form.get("pw", "")):
                request.session["au"] = True
                return RedirectResponse(url=redir, status_code=303)
        except argonerr.VerifyMismatchError as err:
            print(err)
            error = "The password did not match"
        except argonerr.VerificationError as err:
            print(err)
            error = "Something went wrong with the password check"
        return tpl.TemplateResponse(
            "login.html",
            {"noscript": True, "redir": redir, "error": error, "request": request},
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
