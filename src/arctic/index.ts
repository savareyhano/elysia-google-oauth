// Docs:
// https://arcticjs.dev/providers/google

import { Elysia } from 'elysia'
import { ArcticFetchError, generateCodeVerifier, generateState, Google, OAuth2RequestError } from 'arctic'

const google = new Google(
  process.env.GOOGLE_CLIENT_ID!,
  process.env.GOOGLE_CLIENT_SECRET!,
  process.env.GOOGLE_REDIRECT_URI!
)

const app = new Elysia()
  .get('/', () => 'Hello Elysia')
  .get(
    '/auth/google',
    async ({ redirect, cookie: { google_state, google_code_verifier } }) => {
      const state = generateState()
      const codeVerifier = generateCodeVerifier()
      // More information:
      // https://developers.google.com/identity/openid-connect/openid-connect
      const scopes = ['openid', 'profile', 'email']
      const url = google.createAuthorizationURL(state, codeVerifier, scopes)
      url.searchParams.set('access_type', 'offline')

      google_state.value = state
      google_state.set({
        secure: false, // set to true in production
        path: '/',
        httpOnly: true,
        maxAge: 60 * 10, // 10 min
      })

      google_code_verifier.value = codeVerifier
      google_code_verifier.set({
        secure: false, // set to true in production
        path: '/',
        httpOnly: true,
        maxAge: 60 * 10, // 10 min
      })

      return redirect(url.toString())
    }
  )
  .get(
    '/auth/google/callback',
    async ({ query, cookie: { google_state, google_code_verifier } }) => {
      const { code, state } = query
      const storedState = google_state.value
      const storedCodeVerifier = google_code_verifier.value

      if (
        code === null ||
        storedState === null ||
        state !== storedState ||
        storedCodeVerifier === null
      ) {
        // 400
        throw new Error('Invalid request')
      }

      try {
        const tokens = await google.validateAuthorizationCode(
          code as string,
          storedCodeVerifier as string
        )
        const accessToken = tokens.accessToken()
        // More information:
        // https://developers.google.com/identity/openid-connect/openid-connect
        const response = await fetch(
          'https://openidconnect.googleapis.com/v1/userinfo',
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          }
        )
        const user = await response.json()
        return user
      } catch (error) {
        if (error instanceof OAuth2RequestError) {
          // Invalid authorization code, credentials, or redirect URI
          const code = error.code
          // ...
          console.log(code)
        }
        if (error instanceof ArcticFetchError) {
          // Failed to call `fetch()`
          const cause = error.cause
          // ...
          console.log(cause)
        }
        // Parse error
        console.log(error)
      }
    }
  )
  .listen(3000)

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
)
