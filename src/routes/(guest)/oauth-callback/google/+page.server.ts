import { redirect } from '@sveltejs/kit'
import { upsertUserFromOauth } from '$lib/server/functions/user.js';
import { createUserSession } from '$lib/server/utils/session.js';
import GoogleOauth from '$lib/server/utils/oauth';


export const load = async ({ url, cookies }) => {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    const [validateSuccess, storedCodeVerifier] = GoogleOauth.validateCodeAndState(cookies, { code, state })
    if(!validateSuccess) return redirect(300, '/')
    
    const { user_info, accessToken } = await GoogleOauth.getGoogleUserInfo(code as string, storedCodeVerifier as string, )
    if(!user_info || !accessToken) return redirect(300, '/')
    
    const user = await upsertUserFromOauth({
        email: user_info.email,
        name: user_info.name,
        provider: "GOOGLE",
        providerId: user_info.sub,
        picture: user_info.picture,
        access_token: accessToken

    }) 
    if(!user) return redirect(302, '/')

    await createUserSession(user.id, cookies)
    return redirect(302, '/dashboard')
}


