import { Controller } from '@hotwired/stimulus';

/*
 * The calls of /api-calls, made from the browser with the access token the page carries: the token travels
 * in the "Authorization" header as RFC 6750 §2.1 says, and what comes back is shown as it came back, status
 * line, the headers that say something, and the body.
 *
 * The page declares the calls (src/Api/Console/CallsOfThePage.php) and this reads them off the button, so a
 * call added there needs nothing here.
 */
export default class extends Controller {
    static values = { tokenSelector: String };

    async send(event) {
        const { call, method, path, body } = event.params;
        const answer = this.element.querySelector(`[data-api-answer="${call}"]`);
        const token = document.querySelector(this.tokenSelectorValue)?.value?.trim() ?? '';

        answer.hidden = false;
        answer.textContent = `${method} ${path}\nAuthorization: Bearer ${token.slice(0, 12)}…\n\nwaiting…`;

        const headers = { Accept: 'application/json', Authorization: `Bearer ${token}` };
        if (body) {
            headers['Content-Type'] = 'application/json';
        }

        try {
            const response = await fetch(path, { method, headers, body: body || undefined });
            const text = await response.text();
            // what a refusal says is in a header: the challenge of RFC 6750 §3 names the realm, the error
            // and, for a missing scope, the scope
            const challenge = response.headers.get('www-authenticate');
            answer.textContent = [
                `${method} ${path}`,
                `Authorization: Bearer ${token.slice(0, 12)}…`,
                '',
                `HTTP ${response.status} ${response.statusText}`,
                challenge ? `WWW-Authenticate: ${challenge}` : null,
                `Content-Type: ${response.headers.get('content-type') ?? ''}`,
                '',
                this.constructor.pretty(text),
            ].filter((line) => line !== null).join('\n');
        } catch (error) {
            answer.textContent = `${method} ${path}\n\nThe request did not come back: ${error}`;
        }
    }

    static pretty(text) {
        try {
            return JSON.stringify(JSON.parse(text), null, 2);
        } catch {
            return text === '' ? '(no body)' : text;
        }
    }
}
