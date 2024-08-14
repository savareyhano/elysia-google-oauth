# Elysia OAuth Google

## Web server applications

The authorization sequence begins when your application redirects a browser to a Google URL; the URL includes query parameters that indicate the type of access being requested. Google handles the user authentication, session selection, and user consent. The result is an authorization code, which the application can exchange for an access token and a refresh token.

The application should store the refresh token for future use and use the access token to access a Google API. Once the access token expires, the application uses the refresh token to obtain a new one.

![](https://developers.google.com/static/identity/protocols/oauth2/images/flows/authorization-code.png)

Useful references:
- [OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)
- [OAuth 2.0 Scopes for Google APIs](https://developers.google.com/identity/protocols/oauth2/scopes)
- [OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Using OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server)

## Development
To start the development server run:
```bash
bun run dev # for running the google oauth without using any libraries
bun run dev:arctic # for running the google oauth using arctic library
bun run dev:googleapis # for running the google oauth using googleapis library
```

Open http://localhost:3000/auth/google with your browser to see the result.