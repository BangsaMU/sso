@extends('master::layouts.tabler-auth')

{{--
This section injects our custom CSS for the corporate look and feel.
--}}
@push('styles')
<style>
    body {
        background-image: url("{{ asset($settings->get('appearance.background')) }}") !important;
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
    }

    /* A subtle gradient overlay adds more depth than a solid color. */
    body::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(to bottom right, rgba(10, 25, 47, 0.6), rgba(0, 0, 0, 0.7));
        z-index: 0;
    }

    /* Position the main content above the overlay */
    .page {
        z-index: 1;
    }

    /* Revamped login card styles */
    .card {
        border-radius: 0.5rem !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37) !important;
        background-color: rgba(255, 255, 255, 0.98) !important;
    }

    /* Copyright footer styles */
    .auth-footer {
        position: absolute;
        bottom: 1rem;
        width: 100%;
        text-align: center;
        color: rgba(255, 255, 255, 0.7);
        font-size: 0.875rem;
    }
</style>
@endpush

@section('content')
<div class="container-tight p-4">
    <div class="card card-md">
        <div class="card-body p-4">
            <div class="text-center mb-4">
                @php
                    $logoUrl = $settings->get('appearance.logo');
                @endphp

                <a href="." class="navbar-brand navbar-brand-autodark">
                    @if($logoUrl)
                        <img src="{{ asset($logoUrl) }}" height="100" alt="{{ config('app.name') }}" style="height: 100px;">
                    @else
                        <h1 style="color: white;">{{ $settings->get('application.name', config('app.name', 'Laravel')) }}</h1>
                    @endif
                </a>
            </div>
            <h1 class="h1 text-center mb-2 text-gray-400">{{ $settings->get('application.name', config('app.name')) }}</h1>
            <div class="hr-text">
                <span>Login To Your Account</span>
            </div>
            <form method="POST" action="{{ route('login') }}">
                @csrf

                {{-- Email Input with Icon --}}
                <div class="mb-3">
                    <label class="form-label">Email address</label>
                    <div class="input-group">
                        <span class="input-group-text">
                            <svg xmlns="https://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none" /><path d="M3 7a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-10z" /><path d="M3 7l9 6l9 -6" /></svg>
                        </span>
                        <input type="email" name="email" class="form-control @error('email') is-invalid @enderror" value="{{ old('email') }}" required autofocus placeholder="your@email.com">
                    </div>
                    @error('email')
                    <div class="invalid-feedback d-block">{{ $message }}</div>
                    @enderror
                </div>

                {{-- Password Input with Icon --}}
                <div class="mb-3">
                    <label class="form-label">Password</label>
                    <div class="input-group">
                        <span class="input-group-text">
                            <svg xmlns="https://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none" /><path d="M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6z" /><path d="M11 16a1 1 0 1 0 2 0a1 1 0 0 0 -2 0" /><path d="M8 11v-4a4 4 0 0 1 8 0v4" /></svg>
                        </span>
                        <input type="password" name="password" class="form-control @error('password') is-invalid @enderror" required placeholder="Your password">
                    </div>
                    @error('password')
                    <div class="invalid-feedback d-block">{{ $message }}</div>
                    @enderror
                </div>

                <div class="mb-2">
                    <label class="form-check">
                        <input type="checkbox" class="form-check-input" name="remember" id="remember_me">
                        <span class="form-check-label">Remember me on this device</span>
                    </label>
                </div>

                <div class="form-footer">
                    {{-- THIS IS THE CORRECTED LINE --}}
                    <button type="submit" class="btn btn-primary w-100" id="login-submit-btn">Sign in {{ config('SsoConfig.main.ACTIVE') ? 'with SSO' : '' }}</button>
                </div>

                <div class="mt-2">
                    <div class="text-center">
                        <a href="{{ route('password.request') }}" class="text-decoration-none">
                            Forgot your password?
                        </a>
                    </div>
                </div>

                {{-- Login Attempts Warning --}}
                {{-- @if(session()->has('login_attempts_warning'))
                    <div class="alert alert-warning mt-3 mb-0" role="alert">
                        <div class="d-flex">
                            <div>
                                <svg xmlns="https://www.w3.org/2000/svg" class="icon alert-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 9v2m0 4v.01"/><path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75"/></svg>
                            </div>
                            <div>
                                <h4 class="alert-title">Login Attempts Warning</h4>
                                <div class="text-muted">{{ session('login_attempts_warning') }}</div>
                            </div>
                        </div>
                    </div>
                @endif --}}
            </form>
        </div>
    </div>
</div>

<div class="auth-footer">
    Copyright &copy; {{ date('Y') }} {{ $settings->get('application.name', config('app.name')) }}. Meindo IT Dev
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.querySelector('form');
    const submitBtn = document.getElementById('login-submit-btn');

    if (loginForm && submitBtn) {
        loginForm.addEventListener('submit', function(e) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Signing in...';

            // Re-enable after 10 seconds in case form submission fails
            setTimeout(function() {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Sign in {{ config('SsoConfig.main.ACTIVE') ? 'with SSO' : '' }}';
            }, 10000);
        });
    }

    // Auto-refresh page when lockout timer expires to re-enable login form
    const urlParams = new URLSearchParams(window.location.search);
    const lockoutEnds = urlParams.get('lockout_until');
    if (lockoutEnds) {
        const lockoutTime = parseInt(lockoutEnds);
        const currentTime = Math.floor(Date.now() / 1000);

        if (lockoutTime > currentTime) {
            const remainingSeconds = lockoutTime - currentTime;
            setTimeout(function() {
                window.location.href = window.location.pathname;
            }, remainingSeconds * 1000);
        }
    }
});
</script>
@endsection
