import { lucia } from "$lib/server/utils/auth";
import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import GoogleOauth from "$lib/server/utils/oauth";
import { findUserByEmail } from "$lib/server/functions/user";


export const load:PageServerLoad = async () => {
	return redirect(302, '/');
}

export const actions: Actions = {
	default: async (event) => {
		if (!event.locals.session) return fail(401);
		
		if(event.locals.user?.provider && event.locals.user.provider == "GOOGLE") {
			// TODO: call revoke goole access token
			// const user = await findUserByEmail(event.locals.user.email)
			// if(!user) return fail(401)
			// if(!user.access_token) return fail(401)
			// await GoogleOauth.revokeGoogleToken(user.access_token)
		}

		await lucia.invalidateSession(event.locals.session.id);
		const sessionCookie = lucia.createBlankSessionCookie();
		event.cookies.set(sessionCookie.name, sessionCookie.value, {
			path: ".",
			...sessionCookie.attributes
		});
		redirect(302, "/");
	}
};