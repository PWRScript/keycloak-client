# -*- coding: utf-8 -*-
from quart import Quart, Response, Request, redirect
from quart.globals import request, session, current_app
from quart.sessions import SecureCookieSession

from quart.typing import Callable
from functools import wraps

import json

from .. import Client

class AuthenticationMiddleware:
    def __init__(self, app: Quart, callback_url: str = "http://localhost:5000/kc/callback",login_uri: str = "/", login_redirect_uri: str = "/home", logout_uri: str = "/kc/logout", logout_redirect_uri: str = "/", already_authorized_force_login=False) -> None:
        """
        Provides access to a simple Quart extension which allows to integrate keycloak authorization in your app and protect routes / identify users.
        Must be initialized without wrapping ASGI (this doesn´t let your app start) using AuthenticationMiddleware(app) and aditional parameters if needed

        :param app: Quart App
        :param callback_url: The callback url to process and validade the keycloak authorization
        :param login_uri: Uri used to start the authorization flow (redirects to keycloak)
        :param login_redirect_uri: Uri to redirect after successfuly authorization
        :param logout_uri: Uri used to logout and desauthorize
        :param logout_redirect_uri: Uri to redirect after successfuly logout
        :param already_authorized_force_login: Specifies if already authorized, the login should be enforced (true) or redirects to login_redirect_uri keeping the old authorization (false)
        """
        self.app = app
        self.callback_url = callback_url
        self.login_uri = login_uri
        self.login_redirect_uri = login_redirect_uri
        self.logout_uri = logout_uri
        self.logout_redirect_uri = logout_redirect_uri
        self.already_authorized_force_login = already_authorized_force_login
        self.kc = Client(self.callback_url)
        if app is not None:
            self.init_app(app)


    async def before_request(self):
        response = None
        session: SecureCookieSession = await self.app.session_interface.open_session(app=self.app,request=request)
        if request.base_url == self.callback_url:
            response = await self.kc_callback(request, session)
        elif request.path == self.logout_uri:
            response = await self.kc_logout(session)
        elif request.path == self.login_uri and (self.already_authorized_force_login or (not self.already_authorized_force_login and session.get("user") is None)):
            response = await self.kc_login(session)
        elif request.path == self.login_uri and not self.already_authorized_force_login and session.get("user") is not None:
            response = redirect(self.login_redirect_uri)


        await self.app.session_interface.save_session(self.app, session, response)

        return response


    async def kc_callback(self, request: Request, session: SecureCookieSession):
        state = request.args.get("state", "unknown")
        _state = session.pop("state", None)
        if state != _state:
            return Response("Invalid state", status=403)
        code: str = request.args.get("code", "unknown")
        tokens = await self.kc.async_callback(code)
        session["tokens"] = json.dumps(tokens)

        access_token = tokens["access_token"]
        user = await self.kc.async_fetch_userinfo(access_token)
        session["user"] = json.dumps(user)

        return redirect(self.login_redirect_uri)

    async def kc_logout(self, session: SecureCookieSession):
        if "tokens" in session:
            tokens = json.loads(session["tokens"])
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]
            await self.kc.async_logout(access_token, refresh_token)
            session.pop("tokens")
            try:
                del session["tokens"]
            except:
                pass

        if "user" in session:
            session.pop("user")
            try:
                del session["user"]
            except:
                pass

        return redirect(self.logout_redirect_uri)

    async def kc_login(self, session: SecureCookieSession):
        url, state = self.kc.login()
        session["state"] = state
        return redirect(url)

    def init_app(self, app: Quart) -> None:
        if type(app) != Quart:
            raise RuntimeError("You must initialize this extension without wrapping ASGI in your app. This can be achieved using AuthenticationMiddleware(app) and other needed parameters")
        app.keycloak = self
        app.before_request(self.before_request)
        self.app = app

class AuthenticationRequiredException(BaseException):
    """
    To access this route is authentication is required
    Please authenticate yourself first then proceed
    """
    pass


def login_required(force_login_redirect: bool = True):
    """
    Makes this route only accessible when authenticated

    :param force_login_redirect: If the user is unauthenticated, should we throw a exception (False) or redirect the user to login (True)
    """
    def decorator(route_func:Callable):
        @wraps(route_func)
        async def wrapper(*args, **kwargs):
            """Forces the user to be logged in when accessing the wrapped route"""
            if session.get("user") is not None:
                return await route_func(*args, **kwargs)
            elif not force_login_redirect:
                raise AuthenticationRequiredException
            else:
                return redirect(current_app.keycloak.login_uri)
        return wrapper
    return decorator
