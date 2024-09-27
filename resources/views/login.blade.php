@extends('sso::auth.auth-page', ['auth_type' => 'login'])

@section('adminlte_css_pre')
    {{-- <link rel="stylesheet" href="{{ asset('vendor/icheck-bootstrap/icheck-bootstrap.min.css') }}"> --}}
@stop

@php($login_url = View::getSection('login_url') ?? config('adminlte.login_url', 'login'))
@php($register_url = View::getSection('register_url') ?? config('adminlte.register_url', 'register'))
@php($password_reset_url = View::getSection('password_reset_url') ?? config('adminlte.password_reset_url', 'password/reset'))

@if (config('adminlte.use_route_url', false))
    @php($login_url = $login_url ? route($login_url) : '')
    @php($register_url = $register_url ? route($register_url) : '')
    @php($password_reset_url = $password_reset_url ? route($password_reset_url) : '')
@else
    @php($login_url = $login_url ? url($login_url) : '')
    @php($register_url = $register_url ? url($register_url) : '')
    @php($password_reset_url = $password_reset_url ? url($password_reset_url) : '')
@endif

@section('auth_header', __('login_message'))

@section('auth_body')
    <form action="{{ $login_url }}" method="post">
        @csrf

        {{-- Email field --}}
        <div class="input-group mb-3">
            <input type="email" name="email" class="form-control @error('email') is-invalid @enderror"
                value="{{ old('email') }}" placeholder="{{ __('email') }}" autofocus>

                <div class="input-group-text">
                    <span class="bi bi-envelope {{ config('adminlte.classes_auth_icon', '') }}"></span>
                </div>



            @error('email')
                <span class="invalid-feedback" role="alert">
                    <strong>{{ $message }}</strong>
                </span>
            @enderror
        </div>

        {{-- Password field --}}
        <div class="input-group mb-3">
            <input type="password" name="password" class="form-control @error('password') is-invalid @enderror"
                placeholder="{{ __('password') }}">

                <div class="input-group-text">
                    <span class="bi bi-lock-fill {{ config('adminlte.classes_auth_icon', '') }}"></span>
                </div>


            @error('password')
                <span class="invalid-feedback" role="alert">
                    <strong>{{ $message }}</strong>
                </span>
            @enderror
        </div>

        {{-- Login field --}}
        <div class="row">
            <div class="col">
                <div class="icheck-primary" title="">
                    <input type="checkbox" name="remember" id="remember" {{ old('remember') ? 'checked' : '' }}>

                    <label for="remember">
                        {{ __('remember_me') }}
                    </label>
                </div>
            </div>

            <div class="col">
                <button type=submit
                    class="btn btn-block rounded {{ config('adminlte.classes_auth_btn', 'btn-flat btn-primary') }}">
                    <span class="fas fa-sign-in-alt"></span>
                    {{ __('sign_in') }} {{ config('SsoConfig.main.ACTIVE') ? 'with SSO' : '' }}
                </button>
            </div>
        </div>

    </form>
@stop

@section('auth_footer')
    {{-- Password reset link --}}
    @if ($password_reset_url)
        <p class="my-0">
            <a href="{{ $password_reset_url }}">
                {{ __('i_forgot_my_password') }}
            </a>
        </p>
    @endif

    {{-- Register link --}}
    @if ($register_url && !config('SsoConfig.main.ACTIVE'))
        <p class="my-0">
            <a href="{{ $register_url }}">
                {{ __('register_a_new_membership') }}
            </a>
        </p>
    @endif
@stop
