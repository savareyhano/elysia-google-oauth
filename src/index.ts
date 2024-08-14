// Docs:
// https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow

import { Elysia } from 'elysia'
import crypto from 'crypto'
import qs from 'querystring'

interface GoogleUserResult {
  id: string
  email: string
  verified_email: boolean
  name: string
  given_name: string
  family_name: string
  picture: string
  locale: string
}

interface GoogleTokensResult {
  access_token: string
  expires_in: Number
  refresh_token: string
  scope: string
  id_token: string
}

const getGoogleUser = async ({ id_token, access_token }: any): Promise<GoogleUserResult> => {
  try {
    const res = await fetch(`https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`, {
      headers: {
        Authorization: `Bearer ${id_token}`
      }
    })

    return await res.json()
  } catch (error: any) {
    console.error(error)
    throw new Error(error.message)
  }
}

const getGoogleOAuthTokens = async (code: string): Promise<GoogleTokensResult> => {
  const tokenUrl = 'https://oauth2.googleapis.com/token'

  // More info:
  // https://cloud.google.com/apigee/docs/api-platform/security/oauth/access-tokens
  const values = {
    code,
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    grant_type: 'authorization_code',
  }

  try {
    const res = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: qs.stringify(values),
    })

    return await res.json()
  } catch (error: any) {
    console.error(error.response.data.error)
    throw new Error(error.message)
  }
}

const app = new Elysia()
  .get('/', () => 'Hello Elysia')
  .get('/auth/google', ({ redirect, cookie: { google_state } }) => {
    // More info:
    // https://accounts.google.com/.well-known/openid-configuration
    const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth'

    const state = crypto.randomBytes(32).toString('hex')

    const options = {
      redirect_uri: process.env.GOOGLE_REDIRECT_URI as string,
      client_id: process.env.GOOGLE_CLIENT_ID as string,
      // for getting the refresh token access_type is set to 'offline'
      access_type: 'offline',
      // for getting the code which we will use for later
      response_type: 'code',
      // google consent page
      prompt: 'consent',
      // which data we want to get from google
      scope: [
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
      ].join(' '),
      // Using state to reduce the risk of CSRF attacks.
      state: state,
    }

    const qs = new URLSearchParams(options)

    const url = `${rootUrl}?${qs.toString()}`

    google_state.value = state
    google_state.set({
      secure: false, // set to true in production
      path: '/',
      httpOnly: true,
      maxAge: 60 * 10, // 10 min
    })

    return redirect(url)
  })
  .get('/auth/google/callback', async ({ query, cookie: { google_state } }) => {
    const { code, state } = query
    const storedState = google_state.value

    if (code === null || storedState === null || state !== storedState) {
      // 400
      throw new Error('Invalid request')
    }

    const { id_token, access_token } = await getGoogleOAuthTokens(code as string)

    const googleUser = await getGoogleUser({ id_token, access_token })

    return googleUser
  })
  .listen(3000)

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
)
