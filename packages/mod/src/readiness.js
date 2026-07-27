const POLL_INTERVAL = 250;

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(check) {
    for (;;) {
        const value = check();
        if (value != null) return value;
        await sleep(POLL_INTERVAL);
    }
}

export const waitForLogin = () => waitFor(() => {
    const n = globalThis.Player?.MemberNumber;
    return typeof n === 'number' ? n : null;
});

export const waitForModSdk = () => waitFor(() => globalThis.bcModSdk);