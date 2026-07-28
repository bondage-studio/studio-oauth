const POLL_INTERVAL = 250;

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor<T>(check: () => T | null | undefined): Promise<T> {
    for (;;) {
        const value = check();
        if (value != null) return value;
        await sleep(POLL_INTERVAL);
    }
}

export const waitForLogin = (): Promise<number> => waitFor(() => {
    const n = globalThis.Player?.MemberNumber;
    return typeof n === 'number' ? n : null;
});

export const waitForModSdk = (): Promise<ModSDKGlobalAPI> =>
    waitFor(() => (typeof bcModSdk === 'undefined' ? null : bcModSdk));
