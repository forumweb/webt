import React, { useState } from 'react';
import { X, Tag } from 'lucide-react';
import { Category } from '../types/forum';
import { useAuth } from '../context/AuthContext';

interface CreateThreadModalProps {
  isOpen: boolean;
  onClose: () => void;
  categories: Category[];
}

export default function CreateThreadModal({ isOpen, onClose, categories }: CreateThreadModalProps) {
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { user } = useAuth();

  // Add tag (max 5, enter key)
  const handleAddTag = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && tagInput.trim() && tags.length < 5) {
      e.preventDefault();
      setTags([...tags, tagInput.trim()]);
      setTagInput('');
    }
  };

  const handleRemoveTag = (index: number) => {
    setTags(tags.filter((_, i) => i !== index));
  };

  // Submit create thread
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!title.trim() || !content.trim() || !selectedCategory) {
      setError("Semua field wajib diisi.");
      return;
    }
    if (!user) {
      setError("Harus login untuk membuat thread.");
      return;
    }
    setLoading(true);
    try {
      // Find selected category object
      const categoryObj = categories.find(cat => cat.id === selectedCategory);
      if (!categoryObj) {
        setError("Kategori tidak valid.");
        setLoading(false);
        return;
      }

      // Prepare thread data
      const threadData = {
        title: title.trim(),
        content: content.trim(),
        author: {
          id: user.email || String(Date.now()),
          username: user.name || user.email || 'User',
          avatar: user.avatar,
          reputation: user.reputation || 0,
        },
        category: categoryObj,
        tags,
        isPinned: false,
        isLocked: false,
        votes: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      // POST ke backend
      const res = await fetch('http://localhost:3000/threads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(threadData),
      });
      if (!res.ok) {
        setError('Gagal membuat thread');
        setLoading(false);
        return;
      }

      // Reset form & tutup modal
      setTitle('');
      setContent('');
      setSelectedCategory('');
      setTags([]);
      setTagInput('');
      setError('');
      setLoading(false);
      onClose();
    } catch (err) {
      setError('Gagal membuat thread');
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-2 sm:p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto flex flex-col border border-gray-200">
        {/* Header modal */}
        <div className="flex items-center justify-between p-5 border-b border-gray-200">
          <h2 className="text-xl font-extrabold text-gray-900">Create New Thread</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition"
            aria-label="Tutup modal"
          >
            <X size={22} />
          </button>
        </div>
        {/* Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-6">
          <div>
            <label htmlFor="title" className="block text-sm font-bold text-gray-700 mb-1">
              Title *
            </label>
            <input
              type="text"
              id="title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Judul thread"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none font-semibold"
              required
              autoFocus
              disabled={loading}
            />
          </div>
          <div>
            <label htmlFor="category" className="block text-sm font-bold text-gray-700 mb-1">
              Category *
            </label>
            <select
              id="category"
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none font-semibold"
              required
              disabled={loading}
            >
              <option value="">Pilih kategori</option>
              {categories.map((category) => (
                <option key={category.id} value={category.id}>
                  {category.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="content" className="block text-sm font-bold text-gray-700 mb-1">
              Content *
            </label>
            <textarea
              id="content"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Tulis isi thread, pertanyaan, diskusi..."
              rows={8}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none font-semibold resize-none"
              required
              disabled={loading}
            />
            <p className="text-xs text-gray-400 mt-1">Markdown supported</p>
          </div>
          <div>
            <label htmlFor="tags" className="block text-sm font-bold text-gray-700 mb-1">
              Tags (opsional)
            </label>
            <div className="border border-gray-300 rounded-lg p-3 focus-within:ring-2 focus-within:ring-blue-500 focus-within:border-transparent">
              <div className="flex flex-wrap gap-2 mb-2">
                {tags.map((tag, index) => (
                  <span
                    key={index}
                    className="inline-flex items-center gap-1 bg-blue-100 text-blue-700 px-2 py-1 rounded-full text-sm font-semibold"
                  >
                    <span>{tag}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveTag(index)}
                      className="hover:bg-blue-200 rounded-full p-0.5 transition"
                      aria-label="Remove tag"
                      disabled={loading}
                    >
                      <X size={12} />
                    </button>
                  </span>
                ))}
              </div>
              <input
                type="text"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={handleAddTag}
                placeholder={tags.length < 5 ? "Tambah tag dan tekan Enter" : "Max 5 tags"}
                disabled={tags.length >= 5 || loading}
                className="w-full outline-none font-semibold"
              />
            </div>
            <p className="text-xs text-gray-400 mt-1">Tekan Enter untuk tambah tag (max 5)</p>
          </div>
          {error && <div className="text-red-600 text-sm mb-2">{error}</div>}
          <div className="flex items-center justify-end gap-4 pt-4 border-t border-gray-200">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 hover:text-blue-700 font-semibold transition"
              aria-label="Batal"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!title.trim() || !content.trim() || !selectedCategory || loading}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white px-6 py-2 rounded-lg font-bold transition"
              aria-label="Buat thread"
            >
              {loading ? 'Creating...' : 'Create Thread'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
