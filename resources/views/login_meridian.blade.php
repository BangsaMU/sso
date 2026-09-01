<!doctype html>
<html lang="en" data-theme="light">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link rel="icon" type="image/svg+xml"
        href='data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><style>.t{fill:%230a0a0a}.m{stroke:%23fafafa}@media (prefers-color-scheme: dark){.t{fill:%23fafafa}.m{stroke:%230a0a0a}}</style><rect class="t" width="512" height="512" rx="112"/><path class="m" d="M 392 144 H 200 A 56 56 0 0 0 200 256 H 312 A 56 56 0 0 1 312 368 H 120" fill="none" stroke-width="76" stroke-linecap="round" stroke-linejoin="round"/></svg>' />
    <script>
        (function () {
            var t = localStorage.getItem("stisla-theme");
            if (t === "dark" || t === "light") document.documentElement.dataset.theme = t;
        })();
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
    <title>Sign in · {{ config('app.name', 'Meridian') }}</title>
    <link rel="stylesheet" href="{{ asset('assets/css/meridian.css') }}" />
</head>
<body class="bg-background text-foreground antialiased min-h-screen">
    <main class="auth flex min-h-screen">
        <section class="auth__panel flex-1 flex flex-col justify-between p-8 md:p-12 relative bg-surface">
            <button type="button" class="button button--ghost button--neutral button--icon-only auth__toggle absolute top-6 end-6"
                data-theme-toggle aria-label="Toggle theme">
                <i class="fas fa-moon dark:hidden"></i>
                <i class="fas fa-sun hidden dark:inline-block"></i>
            </button>

            <div class="auth__form max-w-md w-full mx-auto my-auto flex flex-col gap-6">
                <div>
                    <h1 class="text-3xl font-bold tracking-tight text-foreground m-0">Welcome back</h1>
                    <p class="text-sm text-muted-foreground mt-1">
                        Sign in to your {{ config('app.name', 'Meridian') }} account.
                    </p>
                </div>

                @if(session()->has('login_attempts_warning'))
                    <div class="alert alert--warning p-4 rounded-md border border-warning text-sm">
                        <div class="font-semibold mb-1">Login Attempts Warning</div>
                        <div>{{ session('login_attempts_warning') }}</div>
                    </div>
                @endif

                <form method="POST" action="{{ route('login') }}" class="flex flex-col gap-4">
                    @csrf

                    <div class="field flex flex-col gap-1">
                        <label for="loginEmail" class="field__label text-sm font-medium text-foreground">Email</label>
                        <div class="relative flex items-center">
                            <span class="absolute start-3 text-muted-foreground">
                                <i class="fas fa-envelope"></i>
                            </span>
                            <input type="email" name="email" id="loginEmail"
                                class="input w-full ps-10 @error('email') border-danger @enderror"
                                value="{{ old('email') }}" placeholder="your@email.com" required autofocus autocomplete="email" />
                        </div>
                        @error('email')
                            <span class="field__error text-xs text-danger mt-1">{{ $message }}</span>
                        @enderror
                    </div>

                    <div class="field flex flex-col gap-1">
                        <div class="flex items-center justify-between gap-2">
                            <label for="loginPassword" class="field__label text-sm font-medium text-foreground">Password</label>
                            @if (Route::has('password.request'))
                                <a href="{{ route('password.request') }}" class="text-xs text-primary hover:underline">Forgot?</a>
                            @endif
                        </div>
                        <div class="relative flex items-center">
                            <span class="absolute start-3 text-muted-foreground">
                                <i class="fas fa-lock"></i>
                            </span>
                            <input type="password" name="password" id="loginPassword"
                                class="input w-full ps-10 pe-10 @error('password') border-danger @enderror"
                                placeholder="••••••••••" required autocomplete="current-password" />
                            <button type="button" class="absolute end-3 text-muted-foreground hover:text-foreground"
                                data-password-toggle aria-controls="loginPassword" aria-label="Show password">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                        @error('password')
                            <span class="field__error text-xs text-danger mt-1">{{ $message }}</span>
                        @enderror
                    </div>

                    <div class="flex items-center gap-2 mt-1">
                        <input class="checkbox" type="checkbox" name="remember" id="loginRemember" {{ old('remember') ? 'checked' : '' }} />
                        <label class="text-sm text-muted-foreground cursor-pointer" for="loginRemember">Keep me signed in</label>
                    </div>

                    <button type="submit" class="button button--primary button--block button--lg font-semibold mt-2" id="login-submit-btn">
                        Sign in {{ config('SsoConfig.main.ACTIVE') ? 'with SSO' : '' }}
                        <i class="fas fa-arrow-right ms-2"></i>
                    </button>
                </form>

                <p class="text-center text-xs text-muted-foreground mt-4">
                    &copy; {{ date('Y') }} {{ config('app.name', 'Clay') }}. All rights reserved.
                </p>
            </div>
            <div></div>
        </section>

        <aside class="auth__aside hidden lg:flex flex-1 flex-col justify-between p-12 bg-surface-2 border-s border-border relative overflow-hidden">
            <a href="/" class="auth__brand flex items-center gap-3">
                <span class="auth__brand-mark text-primary text-2xl">
                    <i class="fas fa-layer-group"></i>
                </span>
                <span class="auth__brand-text font-bold text-xl text-foreground">
                    {{ config('app.name', 'Meridian') }}
                </span>
            </a>
            <div class="auth__pitch my-auto max-w-lg">
                <h2 class="auth__pitch-title font-bold text-3xl text-foreground leading-tight">
                    Enterprise Master Data Management <span class="text-primary block">Calmly & Efficiently.</span>
                </h2>
                <p class="auth__pitch-lede text-muted-foreground mt-4 text-base">
                    Centralized platform for master items, vendors, projects, and organizational workflows.
                </p>
            </div>
        </aside>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/@stisla/vanilla@3/dist/stisla.js"></script>
    <script>
        document.addEventListener("click", function (event) {
            var toggle = event.target.closest("[data-password-toggle]");
            if (!toggle) return;
            var input = document.getElementById(toggle.getAttribute("aria-controls"));
            if (!input) return;
            var reveal = input.type === "password";
            input.type = reveal ? "text" : "password";
            var icon = toggle.querySelector("i");
            if (icon) {
                icon.className = reveal ? "fas fa-eye-slash" : "fas fa-eye";
            }
        });
    </script>
</body>
</html>
