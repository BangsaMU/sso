<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corporate Dashboard</title>
    <style>
        /* Pengaturan Dasar Reset */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Arial, sans-serif;
        }

        body {
            background-color: #f4f6f9; /* Abu-abu sangat terang khas corporate */
            color: #333333;
            display: flex;
            height: 100vh;
            overflow: hidden;
        }

        /* Struktur Utama */
        .sidebar {
            width: 260px;
            background-color: #ffffff; /* Samping putih bersih */
            color: #333333;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 24px;
            border-right: 1px solid #e2e8f0; /* Garis pembatas tipis */
        }

        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }

        /* Komponen Sidebar */
        .logo {
            font-size: 20px;
            font-weight: 700;
            color: #0f172a; /* Warna teks gelap tegas */
            margin-bottom: 32px;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Simbol dekoratif pengganti logo gambar */
        .logo::before {
            content: "";
            display: inline-block;
            width: 12px;
            height: 24px;
            background-color: #0284c7; /* Biru korporat */
            border-radius: 3px;
        }

        .nav-menu {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .nav-item {
            display: block;
            padding: 12px 16px;
            color: #64748b; /* Abu-abu medium */
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            font-size: 14px;
            transition: all 0.2s;
        }

        .nav-item:hover {
            background-color: #f1f5f9;
            color: #0f172a;
        }

        .nav-item.active {
            background-color: #e0f2fe; /* Biru muda transparan */
            color: #0369a1; /* Biru teks kontras */
            font-weight: 600;
        }

        /* Tombol Logout Laravel */
        .logout-section {
            border-top: 1px solid #e2e8f0;
            padding-top: 16px;
        }

        .logout-btn {
            width: 100%;
            background: none;
            border: none;
            color: #94a3b8;
            padding: 12px 16px;
            text-align: left;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.2s;
        }

        .logout-btn:hover {
            background-color: #fef2f2;
            color: #dc2626; /* Merah tegas saat hover keluar */
        }

        /* Komponen Atas / Header */
        .header {
            background-color: #ffffff;
            padding: 16px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #e2e8f0;
        }

        .header h1 {
            font-size: 18px;
            color: #0f172a;
            font-weight: 600;
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .user-info {
            display: flex;
            flex-direction: column;
            text-align: right;
        }

        .user-name {
            font-size: 14px;
            font-weight: 600;
            color: #1e293b;
        }

        .user-role {
            font-size: 12px;
            color: #64748b;
        }

        .avatar {
            width: 38px;
            height: 38px;
            background-color: #0284c7;
            color: #ffffff;
            border-radius: 4px; /* Kotak rounded khas korporat */
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
        }

        /* Konten Utama */
        .container {
            padding: 32px;
        }

        /* Kartu Statistik */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 24px;
            margin-bottom: 32px;
        }

        .card {
            background-color: #ffffff;
            padding: 24px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
        }

        .card-title {
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .card-value {
            font-size: 26px;
            font-weight: 700;
            color: #0f172a;
            margin: 6px 0;
        }

        .card-desc {
            font-size: 12px;
            color: #16a34a; /* Hijau sukses */
            font-weight: 500;
        }

        /* Area Konten Tengah */
        .main-panel {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
            text-align: center;
        }

        .panel-icon {
            font-size: 40px;
            color: #38bdf8;
            margin-bottom: 16px;
        }

        .panel-title {
            font-size: 16px;
            color: #0f172a;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .panel-text {
            color: #64748b;
            font-size: 14px;
            max-width: 420px;
            margin: 0 auto;
            line-height: 1.6;
        }
    </style>
</head>
<body>

    <!-- Panel Kiri: Navigasi Bersih -->
    <aside class="sidebar">
        <div>
            <div class="logo">CLAY System</div>
            <nav class="nav-menu">
                <a href="#" class="nav-item active">💼 Ringkasan Bisnis</a>
                <a href="#" class="nav-item">📊 Laporan Analitik</a>
                <a href="#" class="nav-item">📂 Manajemen Data</a>
                <a href="#" class="nav-item">⚙️ Konfigurasi</a>
            </nav>
        </div>
        
        <!-- Formulir Keluar Akun Laravel -->
        <div class="logout-section">
            <form method="post" action="{{ route('logout') }}">
                @csrf
                <button type="submit" class="logout-btn">
                    <span>🚪</span> Keluar Sistem
                </button>
            </form>
        </div>
    </aside>

    <!-- Panel Kanan: Konten Utama -->
    <div class="main-content">
        <!-- Atasan / Navbar -->
        <header class="header">
            <h1>Beranda Dashboard</h1>
            <div class="user-profile">
                <div class="user-info">
                    <span class="user-name">{{ auth()->user()->name }}</span>
                    <span class="user-role">{{ auth()->user()->role }}</span>
                </div>
                <div class="avatar">FN</div>
            </div>
        </header>

        <!-- Area Pengisian Data -->
        <main class="container">
            <!-- Grid Informasi Angka Perusahaan -->
            <div class="stats-grid">
                <div class="card">
                    <div class="card-title">Efisiensi Proses</div>
                    <div class="card-value">94.2%</div>
                    <div class="card-desc">▲ +2.4% Kuartal ini</div>
                </div>
                <div class="card">
                    <div class="card-title">Formulir Terproses</div>
                    <div class="card-value">1,280</div>
                    <div class="card-desc" style="color: #0284c7;">Sesuai target</div>
                </div>
                <div class="card">
                    <div class="card-title">Waktu Tanggap</div>
                    <div class="card-value">14 Menit</div>
                    <div class="card-desc">Stabil</div>
                </div>
            </div>

            <!-- Panel Fokus Utama -->
            <div class="main-panel">
                <div class="panel-icon">📊</div>
                <div class="panel-title">Data Aktivitas Kosong</div>
                <p class="panel-text">Sistem siap menerima input baru. Silakan pilih menu manajemen data di sisi kiri untuk memulai rekapitulasi data perusahaan.</p>
            </div>
        </main>
    </div>

</body>
</html>
