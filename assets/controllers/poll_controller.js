import { Controller } from '@hotwired/stimulus';

/*
 * A run that waits on the user, approving at the provider: the server is asked again every few seconds,
 * and the page is reloaded once it says the run ended, so that its proof shows.
 */
export default class extends Controller {
    static values = { url: String, interval: Number };

    connect() {
        this.timer = setInterval(() => this.ask(), Math.max(this.intervalValue, 2) * 1000);
    }

    disconnect() {
        clearInterval(this.timer);
    }

    async ask() {
        const response = await fetch(this.urlValue, { method: 'POST', headers: { Accept: 'application/json' } });
        const answer = await response.json().catch(() => ({ ended: true }));
        if (answer.ended) {
            clearInterval(this.timer);
            window.location.reload();
        }
    }
}
