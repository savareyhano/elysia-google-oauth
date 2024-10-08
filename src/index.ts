// Docs:
// https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow

import { Elysia } from 'elysia'
import crypto from 'crypto'
import querystring from 'querystring'

const getGoogleAuthURL = (state: string) => {
  // More info:
  // https://accounts.google.com/.well-known/openid-configuration
  const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth'
  const options = {
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    client_id: process.env.GOOGLE_CLIENT_ID,
    // For getting the refresh token, the access_type is set to 'offline'
    access_type: 'offline',
    // For getting the code which we will use later
    response_type: 'code',
    // Google consent page
    prompt: 'consent',
    // Which data we want to get from google
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
    ].join(' '),
    // Using state to reduce the risk of CSRF attacks.
    state,
  }

  return `${rootUrl}?${querystring.stringify(options)}`
}

const getTokens = async (code: string) => {
  try {
    // Uses the code to get tokens
    // that can be used to fetch the user's profile
    // More info:
    // https://cloud.google.com/apigee/docs/api-platform/security/oauth/access-tokens
    const tokenURL = 'https://oauth2.googleapis.com/token'
    const values = {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code',
    }

    const getTokens = await fetch(tokenURL, {
      method: 'POST',
      body: querystring.stringify(values),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })

    return await getTokens.json()
  } catch (error) {
    console.log(error)
  }
}

const getGoogleUser = async (access_token: string, id_token: string) => {
  try {
    // Fetch the user's profile with the access token and bearer
    const getGoogleUser = await fetch(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
      {
        headers: {
          Authorization: `Bearer ${id_token}`,
        },
      }
    )

    return await getGoogleUser.json()
  } catch (error) {
    console.log(error)
  }
}

const app = new Elysia()
  .get('/', () => 'Hello Elysia')
  // Getting login URL
  .get('/auth/google', ({ redirect, cookie: { google_state } }) => {
    const state = crypto.randomBytes(32).toString('hex')

    const url = getGoogleAuthURL(state)

    google_state.value = state
    google_state.set({
      secure: false, // set to true in production
      path: '/',
      httpOnly: true,
      maxAge: 60 * 10, // 10 min
    })

    return redirect(url)
  })
  // Getting the user from Google with the code
  .get('/auth/google/callback', async ({ query, cookie: { google_state } }) => {
    const { code, state } = query
    const storedState = google_state.value

    if (code === null || storedState === null || state !== storedState) {
      // 400
      throw new Error('Invalid request')
    }

    const { id_token, access_token } = await getTokens(code as string)

    return await getGoogleUser(access_token, id_token)
  })
  .listen(3000)

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
)
