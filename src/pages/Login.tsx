import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function Login({ onSuccess }: { onSuccess?: () => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!email.trim() || !password.trim()) {
      setError('Email dan password wajib diisi!');
      return;
    }
    setLoading(true);
    try {
      // POST ke backend login
      const res = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), password: password.trim() }),
      });
      if (!res.ok) {
        setError('Email atau password salah!');
        setLoading(false);
        return;
      }
      const user = await res.json();
      login(user);
      setLoading(false);
      if (onSuccess) onSuccess();
    } catch {
      setError('Gagal login, coba lagi nanti.');
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <h2 className="text-xl font-bold mb-4 text-center" style={{ color: '#7b90ff' }}>Login Romusha</h2>
      {error && <div className="mb-2" style={{ color: '#ff3333' }}>{error}</div>}
      <div>
        <label className="block text-sm font-medium mb-1" style={{ color: '#7b90ff' }}>Email</label>
        <input
          type="email"
          className="w-full border rounded-lg px-3 py-2"
          value={email}
          onChange={e => setEmail(e.target.value)}
          required
          autoFocus
          disabled={loading}
          style={{ background: '#181818', color: '#8a6cff', borderColor: '#282828' }}
        />
      </div>
      <div>
        <label className="block text-sm font-medium mb-1" style={{ color: '#7b90ff' }}>Password</label>
        <input
          type="password"
          className="w-full border rounded-lg px-3 py-2"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          disabled={loading}
          style={{ background: '#181818', color: '#8a6cff', borderColor: '#282828' }}
        />
      </div>
      <button
        type="submit"
        disabled={!email.trim() || !password.trim() || loading}
        className="w-full rounded-lg font-semibold transition-colors"
        style={{ background: '#181818', color: '#7b90ff', border: '1px solid #282828' }}
      >
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}

