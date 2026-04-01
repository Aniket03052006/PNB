const auth = window.qArmorAuth;
const dashboardUrl = '/dashboard';

const authForm = document.getElementById('authForm');
const loginModeButton = document.getElementById('loginModeButton');
const signupModeButton = document.getElementById('signupModeButton');
const nameField = document.getElementById('nameField');
const fullNameInput = document.getElementById('fullName');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const submitButton = document.getElementById('submitButton');
const helperCopy = document.getElementById('helperCopy');
const authStatus = document.getElementById('authStatus');
const authTitle = document.getElementById('authTitle');
const authSubtitle = document.getElementById('authSubtitle');

let mode = 'login';
const authReason = new URLSearchParams(window.location.search).get('reason');

function setStatus(message = '', type = '') {
    authStatus.textContent = message;
    authStatus.className = `status${type ? ` ${type}` : ''}`;
}

function setLoading(isLoading) {
    submitButton.disabled = isLoading;
    submitButton.textContent = isLoading
        ? (mode === 'login' ? 'Signing In...' : 'Creating Account...')
        : (mode === 'login' ? 'Login to Dashboard' : 'Create Account');
}

function setMode(nextMode) {
    mode = nextMode;
    const signupMode = mode === 'signup';

    loginModeButton.classList.toggle('active', !signupMode);
    signupModeButton.classList.toggle('active', signupMode);
    nameField.classList.toggle('hidden', !signupMode);

    passwordInput.autocomplete = signupMode ? 'new-password' : 'current-password';
    authTitle.textContent = signupMode ? 'Create your scanner account' : 'Welcome back';
    authSubtitle.textContent = signupMode
        ? 'Create a Supabase account for Q-ARMOR and we will redirect you into the protected dashboard as soon as a session is issued.'
        : 'Use your Supabase credentials to enter the scanner. We validate the token before any API action runs.';
    helperCopy.innerHTML = signupMode
        ? 'Use a real email if your Supabase project enforces email confirmation. If signup returns a live session, the access token is stored immediately.'
        : 'After login, open the browser console and run <code>localStorage.getItem("token")</code>. If you do not see a long JWT, stop and fix auth before scanning.';
    setStatus('');
}

function redirectToDashboard() {
    window.location.replace(dashboardUrl);
}

async function validateBackendSession(token) {
    if (!token) {
        return { ok: false, message: 'No access token was returned.' };
    }

    try {
        const response = await fetch('/api/auth/me', {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (response.ok) {
            return { ok: true, data: await response.json() };
        }

        let message = 'The backend could not validate your session.';
        try {
            const payload = await response.json();
            message = payload?.detail || payload?.message || message;
        } catch {
            try {
                message = await response.text() || message;
            } catch {
                message = 'The backend could not validate your session.';
            }
        }

        return { ok: false, message };
    } catch (error) {
        return { ok: false, message: error.message || 'Backend session validation failed.' };
    }
}

function applyReasonMessage(reason) {
    if (reason === 'session-expired') {
        setStatus('Your previous session expired or the stored token was invalid. Please log in again.', 'error');
        return;
    }

    if (reason === 'auth-failed') {
        setStatus('The backend could not validate your session. Please sign in again.', 'error');
        return;
    }

    if (reason === 'signed-out') {
        setStatus('You have been signed out.', 'success');
        return;
    }

    if (reason === 'missing-token') {
        setStatus('Please log in to continue to the dashboard.', 'info');
    }
}

async function handleLogin(email, password) {
    const supabase = await auth.getSupabase();
    const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
    });

    if (error) {
        console.error('Login failed:', error.message);
        throw error;
    }

    const token = data.session?.access_token;
    if (!token) {
        throw new Error('Supabase login succeeded but no access token was returned.');
    }
    auth.storeToken(data.session);

    console.log('Token stored');
    const validation = await validateBackendSession(token);
    if (!validation.ok) {
        await auth.signOut();
        throw new Error(validation.message);
    }

    return data.session;
}

async function handleSignup(email, password, fullName) {
    const supabase = await auth.getSupabase();
    const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
            data: {
                full_name: fullName,
            },
        },
    });

    if (error) {
        throw error;
    }

    auth.storeToken(data.session);
    if (data.session?.access_token) {
        console.log('Token stored');
        const validation = await validateBackendSession(data.session.access_token);
        if (!validation.ok) {
            await auth.signOut();
            throw new Error(validation.message);
        }
    }
    return data;
}

authForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    setStatus('');

    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const fullName = fullNameInput.value.trim();

    if (!email || !password) {
        setStatus('Email and password are required.', 'error');
        return;
    }

    setLoading(true);
    try {
        if (mode === 'login') {
            await handleLogin(email, password);
            setStatus('Login successful. Redirecting to the dashboard...', 'success');
            redirectToDashboard();
            return;
        }

        const result = await handleSignup(email, password, fullName);
        if (result.session?.access_token) {
            setStatus('Account created. Redirecting to the dashboard...', 'success');
            redirectToDashboard();
            return;
        }

        setStatus('Account created. Check your email for the confirmation link, then log in.', 'success');
        setMode('login');
    } catch (error) {
        setStatus(error.message || 'Authentication failed.', 'error');
    } finally {
        setLoading(false);
    }
});

loginModeButton.addEventListener('click', () => setMode('login'));
signupModeButton.addEventListener('click', () => setMode('signup'));

window.addEventListener('DOMContentLoaded', async () => {
    setMode('login');

    if (authReason === 'session-expired' || authReason === 'auth-failed' || authReason === 'missing-token') {
        await auth.signOut();
    }

    applyReasonMessage(authReason);

    try {
        const session = await window.qArmorAuthReady;
        if (session?.access_token) {
            const validation = await validateBackendSession(session.access_token);
            if (validation.ok) {
                redirectToDashboard();
                return;
            }

            await auth.signOut();
            setStatus(validation.message, 'error');
        }
    } catch {
        applyReasonMessage(authReason);
    }
});
