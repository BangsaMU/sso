<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">

    <title>{{ config('app.name', 'Laravel') }} - Confirm Password</title>

    <!-- Fonts -->
    <link rel="preconnect" href="https://bunny.net">
    <link href="https://bunny.net/css?family=figtree:400,500,600&display=swap" rel="stylesheet" />

    <!-- Scripts / Tailwind CSS -->
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="font-sans text-gray-900 antialiased">

    <!-- Pembungkus Utama (Pengganti x-guest-layout) -->
    <div class="min-h-screen flex flex-col sm:justify-center items-center pt-6 sm:pt-0 bg-gray-100">
        
        <!-- Wadah Kartu Form -->
        <div class="w-full sm:max-w-md mt-6 px-6 py-4 bg-white shadow-md overflow-hidden sm:rounded-lg">

            <!-- Teks Instruksi -->
            <div class="mb-4 text-sm text-gray-600">
                {{ __('This is a secure area of the application. Please confirm your password before continuing.') }}
            </div>

            <!-- Form Konfirmasi -->
            <form method="POST" action="{{ route('password.confirm') }}">
                @csrf

                <!-- Input Password -->
                <div>
                    <!-- Pengganti x-input-label -->
                    <label for="password" class="block font-medium text-sm text-gray-700">
                        {{ __('Password') }}
                    </label>

                    <!-- Pengganti x-text-input -->
                    <input id="password" 
                           type="password" 
                           name="password" 
                           class="block mt-1 w-full border-gray-300 focus:border-indigo-500 focus:ring-indigo-500 rounded-md shadow-sm"
                           required 
                           autocomplete="current-password" />

                    <!-- Pengganti x-input-error -->
                    @if ($errors->has('password'))
                        <ul class="text-sm text-red-600 space-y-1 mt-2">
                            @foreach ($errors->get('password') as $message)
                                <li>{{ $message }}</li>
                            @endforeach
                        </ul>
                    @endif
                </div>

                <!-- Tombol Submit -->
                <div class="flex justify-end mt-4">
                    <!-- Pengganti x-primary-button -->
                    <button type="submit" class="inline-flex items-center px-4 py-2 bg-gray-800 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-gray-700 focus:bg-gray-700 active:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition ease-in-out duration-150">
                        {{ __('Confirm') }}
                    </button>
                </div>
            </form>

        </div>
    </div>

</body>
</html>
