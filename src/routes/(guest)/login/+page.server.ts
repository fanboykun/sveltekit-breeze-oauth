import { fail, type Action, type Actions, redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { findUser } from "$lib/server/functions/user";
import { loginUserValidation } from "$lib/validation/index.server";
import { createUserSession } from "$lib/server/utils/session";
import { Argon2id } from "oslo/password";
import GoogleOauth from "$lib/server/utils/oauth";

export const load:PageServerLoad = async (event) => {
    if (event.locals.session) {
        return redirect(302, "/dashboard");
    }
}

const login: Action = async ({ cookies, request }) => {
    const data = await request.formData();
    const [ fails, result ] = loginUserValidation(data)

    if(fails) return fail(400, { errors: result, success: false })
    
    const existingUser = await findUser(data)
    if(!existingUser) return fail(300, { message: 'User does not exists', success: false })
    if(existingUser.provider && existingUser.providerId) return fail(300, { message: 'User authenticated with Google, Please Log in With Google Instead', success: false })
    // compare the password here
    if(!await new Argon2id().verify(existingUser.hashed_password, data.get('password') as string)) {
        return fail(500, { message: 'Invalid password', success: false })
    }

    await createUserSession(existingUser.id, cookies)
    redirect(302, "/dashboard");
}

const loginGoogle: Action = async ({ cookies }) => {
    const googleAuthenticationUrl = GoogleOauth.getGoogleAuthenticationUrl(cookies)
    return redirect(302, googleAuthenticationUrl)
}

export const actions: Actions = { login, loginGoogle }