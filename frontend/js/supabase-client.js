import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

const AUTH_CONFIG_ENDPOINT = '/api/auth/config';
const DEFAULT_TOKEN_KEY = 'token';

let authConfigPromise = null;
let authConfigCache = null;
let supabaseClientPromise = null;

function resolveTokenKey() {
    return window.qArmorAuth?.TOKEN_KEY || authConfigCache?.tokenStorageKey || DEFAULT_TOKEN_KEY;
}

function storeToken(session) {
    const token = session?.access_token;
    const tokenKey = resolveTokenKey();

    if (token) {
        localStorage.setItem(tokenKey, token);
        return token;
    }

    localStorage.removeItem(tokenKey);
    return null;
}

function clearToken() {
    localStorage.removeItem(resolveTokenKey());
}

function getToken() {
    return localStorage.getItem(resolveTokenKey());
}

async function loadAuthConfig() {
    if (authConfigCache) {
        return authConfigCache;
    }

    if (!authConfigPromise) {
        authConfigPromise = (async () => {
            const response = await fetch(AUTH_CONFIG_ENDPOINT, { cache: 'no-store' });
            if (!response.ok) {
                throw new Error(`Unable to load auth configuration (${response.status})`);
            }

            const payload = await response.json();
            const missing = Array.isArray(payload?.missing) ? payload.missing : [];
            const tokenStorageKey = payload?.tokenStorageKey || DEFAULT_TOKEN_KEY;

            if (!payload?.configured || !payload?.supabaseUrl || !payload?.supabasePublishableKey) {
                const detail = missing.length
                    ? `Missing auth environment variables: ${missing.join(', ')}`
                    : 'Supabase auth is not configured for this deployment.';
                throw new Error(detail);
            }

            authConfigCache = {
                supabaseUrl: payload.supabaseUrl,
                supabasePublishableKey: payload.supabasePublishableKey,
                tokenStorageKey,
            };
            window.qArmorAuth.TOKEN_KEY = tokenStorageKey;
            return authConfigCache;
        })();
    }

    return authConfigPromise;
}

async function getSupabase() {
    if (!supabaseClientPromise) {
        supabaseClientPromise = (async () => {
            const config = await loadAuthConfig();
            const client = createClient(config.supabaseUrl, config.supabasePublishableKey);
            client.auth.onAuthStateChange((_event, session) => {
                storeToken(session);
            });
            return client;
        })();
    }

    return supabaseClientPromise;
}

async function restoreSession() {
    const supabase = await getSupabase();
    const { data, error } = await supabase.auth.getSession();
    if (error) {
        clearToken();
        throw error;
    }

    storeToken(data.session);
    return data.session ?? null;
}

async function signOut() {
    try {
        const supabase = await getSupabase();
        await supabase.auth.signOut();
    } finally {
        clearToken();
    }
}

window.qArmorAuth = {
    TOKEN_KEY: DEFAULT_TOKEN_KEY,
    loadAuthConfig,
    getSupabase,
    storeToken,
    clearToken,
    getToken,
    restoreSession,
    signOut,
};

window.qArmorAuthReady = restoreSession().catch((error) => {
    console.warn('Supabase session restore failed:', error.message);
    return null;
});
