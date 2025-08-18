import React, { useState } from 'react';

function generateUsername(email: string) {
  return email.split('@')[0] + Math.floor(Math.random() * 1000);
}
export default function Register({ onSuccess }: { onSuccess?: () => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [step, setStep] = useState<'form'|'done'>('form');
  const [registerData, setRegisterData] = useState<any>(null);

  // User agent & screen for device fingerprint
  const userAgent = navigator.userAgent;
  const screen = `${window.screen.width}x${window.screen.height}`;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!email.trim() || !password.trim()) {
      setError('Email dan password wajib diisi!');
      return;
    }
    if (!/@gmail\.com$/i.test(email.trim())) {
      setError('Hanya email Gmail yang diizinkan!');
      return;
    }
    setLoading(true);
    const username = generateUsername(email.trim());
    try {
      const res = await fetch('http://localhost:3000/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          password: password.trim(),
          username,
          userAgent,
          screen,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || 'Gagal register!');
        setLoading(false);
        return;
      }
      // Simpan ke localStorage untuk login otomatis
      localStorage.setItem('fingerprint', data.fingerprint);
      localStorage.setItem('salt', data.salt);
      setRegisterData(data);
      setStep('done');
      setLoading(false);
    } catch {
      setError('Gagal register, coba lagi nanti.');
      setLoading(false);
    }
  };

  if (step === 'done' && registerData) {
    // Halaman "tidak bisa di-close/refresh"
    return (
      <div className="max-w-md mx-auto p-6 bg-white rounded shadow" style={{ minHeight: 400 }}>                                                                           <h2 className="text-xl font-bold mb-4 text-center" style={{ color: '#7b90ff' }}>Registrasi Berhasil!</h2>                                                         <div className="mb-2 text-gray-800 text-center">
          <b>Penting!</b> Simpan QRCode, Secret, dan Paraphrase di bawah ini.              <br />Jangan refresh/close halaman sebelum Anda benar-benar menyimpan semua data!
        </div>                                                                           <div className="mb-4 flex flex-col items-center">
          <img src={registerData.totpQR} alt="QR Code" style={{ width: 128, height: 128 }} />
          <div className="mt-2 text-xs text-gray-700">Scan QRCode di Google Authenticator</div>
        </div>
        <div className="mb-2">
          <label className="block text-sm font-bold mb-1 text-purple-700">TOTP Secret</label>
          <div className="font-mono text-base bg-gray-100 p-2 rounded">{registerData.totpSecret}</div>
        </div>
        <div className="mb-2">
          <label className="block text-sm font-bold mb-1 text-purple-700">Paraphrase (Recovery)</label>
          <div className="font-mono text-xl bg-yellow-100 p-2 rounded text-center tracking-widest">{registerData.paraphrase}</div>
        </div>
        <div className="mb-4 text-xs text-red-500 font-bold text-center">
          Simpan QRCode, Secret, dan Paraphrase di tempat aman.<br/>
          Jika Anda kehilangan data ini, Anda tidak bisa recovery akun!
        </div>
        <button
          className="w-full mt-6 rounded-lg font-semibold py-2"
          style={{ background: '#181818', color: '#7b90ff', border: '1px solid #282828' }}
          onClick={() => {
            setStep('form');
            setRegisterData(null);
            if (onSuccess) onSuccess();
          }}
        >
          Konfirmasi Sudah Disimpan & Login
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-md mx-auto p-6 bg-white rounded shadow space-y-4" style={{ minHeight: 400 }}>
      <h2 className="text-xl font-bold mb-4 text-center" style={{ color: '#7b90ff' }}>Register Romusha Multi-Entitas</h2>
      {error && <div className="mb-2 text-red-500">{error}</div>}
      <div>
        <label className="block text-sm font-medium mb-1" style={{ color: '#7b90ff' }}>Email (hanya Gmail)</label>
        <input
          type="email"
          className="w-full border rounded-lg px-3 py-2"
          value={email}                                                                    onChange={e => setEmail(e.target.value)}
          required
          autoFocus
          disabled={loading}
          style={{ background: '#181818', color: '#8a6cff', borderColor: '#282828' }}
          placeholder="email@gmail.com"
        />
      </div>
      <div>
        <label className="block text-sm font-medium mb-1" style={{ color: '#7b90ff' }}>Password</label>
        <div className="relative">
          <input
            type={showPassword ? "text" : "password"}
            className="w-full border rounded-lg px-3 py-2 pr-10"                             value={password}
            onChange={e => setPassword(e.target.value)}
            required
            disabled={loading}
            style={{ background: '#181818', color: '#8a6cff', borderColor: '#282828' }}
            placeholder="Password"
          />
          <span
            className="absolute right-3 top-2 cursor-pointer"
            title={showPassword ? "Sembunyikan" : "Lihat Password"}
            onClick={() => setShowPassword(s => !s)}
            style={{ color: showPassword ? "#ff0055" : "#8a6cff", fontSize: 22 }}
          >
            {/* Mata custom: psikopat style */}
            {showPassword ? (
              <span role="img" aria-label="hide">👁️‍🗨️</span>
            ) : (
              <span role="img" aria-label="show">👁️</span>
            )}
          </span>
        </div>
      </div>
      <button
        type="submit"
        disabled={!email.trim() || !password.trim() || loading}
        className="w-full rounded-lg font-semibold transition-colors"
        style={{ background: '#181818', color: '#7b90ff', border: '1px solid #282828' }}
      >
        {loading ? 'Memproses...' : 'Register'}
      </button>
    </form>
  );
          }
