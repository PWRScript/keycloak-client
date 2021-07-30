Using Quart Extension
=====================

.. code-block:: python
   :linenos:

    #! /usr/bin/env python
    # -*- coding: utf-8 -*-
    from quart import Quart
    from quart.globals import request
    from keycloak.extensions.quart import AuthenticationMiddleware, login_required


    app = Quart(__name__)
    app.config["SECRET_KEY"] = "secret0123456789"

    AuthenticationMiddleware(
        app,
        callback_url="http://localhost:5000/kc/callback",
        login_redirect_uri="/home",
        logout_redirect_uri="/logout",
    )

    @app.route("/home")
    @login_required(force_login_redirect=True)
    async def home():
        session = await app.session_interface.open_session(app, request)
        user = session["user"]
        return f"Howdy {user}"

    @app.route("/logout")
    async def logout():
        return "User logged out successfully"


    if __name__ == '__main__':
        app.run(port=5000)

