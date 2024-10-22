import { Google, OAuth2RequestError, ArcticFetchError, decodeIdToken, generateCodeVerifier, generateState } from "arctic";
import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_OAUTH_CALLBACK_URI } from "$env/static/private"
import type { Cookies } from "@sveltejs/kit";
import { dev } from "$app/environment";

export type GoogleUserClaim = {
    iss: string,
    azp: string,
    aud: string,
    sub: string,
    email: string,
    email_verified: boolean,
    at_hash: string,
    name: string,
    picture: string,
    given_name: string,
    family_name: string,
    iat: number,
    exp: number
}

const google = new Google(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_OAUTH_CALLBACK_URI)

const getGoogleAuthenticationUrl = (cookies: Cookies) => {
    deleteGoogleStateAndCodeVerifierCookies(cookies)
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const scopes = ["openid", "profile", "email"];
    const url = google.createAuthorizationURL(state, codeVerifier, scopes);

    setGoogleStateAndCodeVerifierCookies(state, codeVerifier, cookies)
    return url
}

const revokeGoogleToken = async (token: string) => {
    try {
        await google.revokeToken(token);
        return true
    } catch (e) {
        console.log(e)
        if (e instanceof OAuth2RequestError) {
            // Invalid authorization code, credentials, or redirect URI
        }
        if (e instanceof ArcticFetchError) {
            // Failed to call `fetch()`
        }
        // Parse error
        return false
    }
}

const validateCodeAndState = ( cookies: Cookies, data: { code: string|null, state: string|null } ) => {
    const storedState = cookies.get("state");
    const storedCodeVerifier = cookies.get("code_verifier");

    const { code, state } = data

    console.log('code: ', code)
    console.log('state: ', state)
    console.log('stored state: ', storedState)
    console.log('stored code verifier: ', storedCodeVerifier)

    if (code === null || 
        storedState === null || 
        storedState === undefined || 
        state !== storedState || 
        storedCodeVerifier === null || 
        storedCodeVerifier === undefined
    ) {
        console.error('Error at validate code and state google oauth, Invalid Request')
        return [false, storedCodeVerifier]
    }
    return [true, storedCodeVerifier]
}

const getGoogleUserInfo = async (code: string, storedCodeVerifier: string) => {
    try {
        const tokens = await google.validateAuthorizationCode(code, storedCodeVerifier);
        const accessToken = tokens.accessToken();
        const idToken = tokens.idToken();
        const user_info = decodeIdToken(idToken) as GoogleUserClaim;

        console.log('access token: ', accessToken)
        console.log('user info: ', user_info)

        return { user_info, accessToken }
    } catch(e) {
        if (e instanceof OAuth2RequestError) {
            console.error('OAuth2RequestError', e)
        }
        if (e instanceof ArcticFetchError) {
            // Failed to call `fetch()`
            const cause = e.cause;
            console.error('ArcticFetchError', cause)
        }
        return { user_info: null, accessToken: null  }
    }

}

const setGoogleStateAndCodeVerifierCookies = (state: string, codeVerifier: string, cookies: Cookies) => {
    // store state as cookie
    cookies.set("state", state, {
        secure: !dev, // set to false in localhost
        path: "/",
        httpOnly: true,
        maxAge: 60 * 10 // 10 min
    });

    // store code verifier as cookie
    cookies.set("code_verifier", codeVerifier, {
        secure: !dev, // set to false in localhost
        path: "/",
        httpOnly: true,
        maxAge: 60 * 10 // 10 min
    });

}

const deleteGoogleStateAndCodeVerifierCookies = (cookies: Cookies) => {

    // store state as cookie
    cookies.delete("state", {
        path: "/",
    });

    // store code verifier as cookie
    cookies.delete("code_verifier", {
        path: "/",
    });

}

const GoogleOauth = { 
    getGoogleAuthenticationUrl, 
    revokeGoogleToken, 
    validateCodeAndState,
    getGoogleUserInfo,
    setGoogleStateAndCodeVerifierCookies,
    deleteGoogleStateAndCodeVerifierCookies
}
export default GoogleOauth