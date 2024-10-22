import { fail, type Action, type Actions, redirect } from "@sveltejs/kit";
import { createUser, findUser } from "$lib/server/functions/user";
import { createUserValidation } from "$lib/validation/index.server";
import { createUserSession } from "$lib/server/utils/session";
import type { PageServerLoad } from "./$types";
import GoogleOauth from "$lib/server/utils/oauth";

export const load:PageServerLoad = async (event) => {
    if (event.locals.session) {
        redirect(302, "/dashboard");
    }
}

const register: Action = async ({ cookies, request }) => {
    const data = await request.formData();
    const [ fails, result ] = createUserValidation(data)

    if(fails) return fail(400, { message: 'Validation failed', errors: result, success: false })
    const existingUser = await findUser(data)
    if(existingUser) {
        if(existingUser.provider && existingUser.providerId) return fail(300, { message: 'User authenticated with Google, Please Log in With Google Instead', success: false })
        else return fail(300, { message: 'User with this email already exist', success: false })
    }
    const newUser = await createUser({ 
            email: data.get('email') as string, 
            name: data.get('name') as string, 
            password: data.get('password') as string,      
        })

    if(!newUser) return fail(500, { message: 'Failed to create user', success: false })
    await createUserSession(newUser.id, cookies)
    redirect(302, "/dashboard");
}

const registerGoogle: Action = async ({ cookies }) => {
    const googleAuthenticationUrl = GoogleOauth.getGoogleAuthenticationUrl(cookies)
    return redirect(302, googleAuthenticationUrl)
}

export const actions: Actions = { register, registerGoogle }