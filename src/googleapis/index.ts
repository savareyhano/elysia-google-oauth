// Docs:
// https://developers.google.com/identity/protocols/oauth2/web-server
// https://googleapis.dev/nodejs/googleapis/latest/docs/

import { Elysia } from 'elysia'
import { google } from 'googleapis'
import crypto from 'crypto'
import url from 'url'

/**
 * To use OAuth2 authentication, we need access to a CLIENT_ID, CLIENT_SECRET, AND REDIRECT_URI
 * from the client_secret.json file. To get these credentials for your application, visit
 * https://console.cloud.google.com/apis/credentials.
 */
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
)

const app = new Elysia()
  .get('/', () => 'Hello Elysia')
  .get('/auth/google', ({ redirect, cookie: { google_state } }) => {
    // Access scopes for Google Account email address and personal info.
    // More info:
    // https://developers.google.com/identity/protocols/oauth2/scopes
    const scopes = [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ]

    // Generate a secure random state value.
    const state = crypto.randomBytes(32).toString('hex')

    // Generate a url that asks permissions for the Google Account email address and personal info scope
    const authorizationUrl = oauth2Client.generateAuthUrl({
      // 'online' (default) or 'offline' (gets refresh_token)
      access_type: 'offline',
      /** Pass in the scopes array defined above.
       * Alternatively, if only one scope is needed, you can pass a scope URL as a string */
      scope: scopes,
      // Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes: true,
      // Include the state parameter to reduce the risk of CSRF attacks.
      state: state,
    })

    google_state.value = state
    google_state.set({
      secure: false, // set to true in production
      path: '/',
      httpOnly: true,
      maxAge: 60 * 10, // 10 min
    })

    return redirect(authorizationUrl)
  })
  // Receive the callback from Google's OAuth 2.0 server.
  .get('/auth/google/callback', async ({ request, cookie: { google_state } }) => {
    // Handle the OAuth 2.0 server response
    let q = url.parse(request.url, true).query

    if (q.error) { // An error response e.g. error=access_denied
      console.log('Error:' + q.error)
    } else if (q.state !== google_state.value) { //check state value
      console.log('State mismatch. Possible CSRF attack')
    } else {
      // Get access and refresh tokens (if access_type is offline)
      let { tokens } = await oauth2Client.getToken(q.code)
      oauth2Client.setCredentials(tokens)

      /** Save credential to the global variable in case access token was refreshed.
       * ACTION ITEM: In a production app, you likely want to save the refresh token
       *              in a secure persistent database instead. */
      // userCredential = tokens

      const oauth2 = google.oauth2({
        auth: oauth2Client,
        version: 'v2'
      })

      const { data } = await oauth2.userinfo.get()

      return data
    }
  })
  .listen(3000)

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
)
