@extends('master::layouts.tabler-auth')

@push('styles')
<style>
    body {
        background-image: url("{{ asset($settings->get('appearance.background')) }}") !important;
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
    }

    body::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; bottom: 0;
        background: linear-gradient(to bottom right, rgba(10, 25, 47, 0.6), rgba(0, 0, 0, 0.7));
        z-index: 0;
    }

    .page {
        z-index: 1;
    }

    .card {
        border-radius: 0.5rem !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37) !important;
        background-color: rgba(255, 255, 255, 0.98) !important;
    }

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
                        <img src="{{ asset($logoUrl) }}" height="50" alt="{{ config('app.name') }}" style="height: 50px;">
                    @else
                        {{-- The h1 for the app name is not needed on this card, logo is enough --}}
                    @endif
                </a>
            </div>

            <h2 class="h2 text-center mb-3">Reset Password</h2>

            <p class="text-muted text-center mb-4">
                Enter your new password below to reset your account.
            </p>

            <form method="POST" action="{{ route('password.store') }}">
                @csrf
                <input type="hidden" name="token" value="{{ $request->route('token') }}">

                {{-- Email Address (Read-only for security) --}}
                <div class="mb-3">
                    <label class="form-label">Email address</label>
                    <div class="input-group">
                        <span class="input-group-text">
                            <svg xmlns="https://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none" /><path d="M3 7a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-10z" /><path d="M3 7l9 6l9 -6" /></svg>
                        </span>
                        <input type="email" name="email" class="form-control @error('email') is-invalid @enderror"
                               value="{{ old('email', $request->email) }}">
                    </div>
                    @error('email')
                        <div class="invalid-feedback d-block">{{ $message }}</div>
                    @enderror
                </div>

                {{-- New Password --}}
                <div class="mb-3">
                    <label class="form-label">New Password</label>
                    <div class="input-group">
                        <span class="input-group-text">
                            <svg xmlns="https://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none" /><path d="M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6z" /><path d="M11 16a1 1 0 1 0 2 0a1 1 0 0 0 -2 0" /><path d="M8 11v-4a4 4 0 0 1 8 0v4" /></svg>
                        </span>
                        <input type="password" name="password" class="form-control @error('password') is-invalid @enderror"
                               required autofocus autocomplete="new-password" placeholder="Enter new password">
                    </div>
                    @error('password')
                        <div class="invalid-feedback d-block">{{ $message }}</div>
                    @enderror
                    <small class="form-hint text-muted">
                        Must be at least 8 characters long.
                    </small>
                </div>

                {{-- Confirm Password --}}
                <div class="mb-3">
                    <label class="form-label">Confirm New Password</label>
                    <div class="input-group">
                        <span class="input-group-text">
                            <svg xmlns="https://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none" /><path d="M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6z" /><path d="M11 16a1 1 0 1 0 2 0a1 1 0 0 0 -2 0" /><path d="M8 11v-4a4 4 0 0 1 8 0v4" /></svg>
                        </span>
                        <input type="password" name="password_confirmation" class="form-control @error('password_confirmation') is-invalid @enderror"
                               required autocomplete="new-password" placeholder="Confirm new password">
                    </div>
                    @error('password_confirmation')
                        <div class="invalid-feedback d-block">{{ $message }}</div>
                    @enderror
                    <small class="form-hint text-muted">
                        Please re-enter your new password to confirm.
                    </small>
                </div>

                <div class="form-footer">
                    <button type="submit" class="btn btn-primary w-100">
                        Reset Password
                    </button>
                </div>
            </form>

            <div class="text-center text-muted mt-3">
                <a href="{{ route('login') }}">Back to Login</a>
            </div>
        </div>
    </div>
</div>

<div class="auth-footer">
    Copyright &copy; {{ date('Y') }} {{ $settings->get('application.name', config('app.name')) }}. Meindo IT Dev
</div>
@endsection
