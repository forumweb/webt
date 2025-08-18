import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Header from './components/Header';                                        import Sidebar from './components/Sidebar';
import ForumHome from './pages/ForumHome';
import Dashboard from './pages/Dashboard';                                       import Profile from './pages/Profile';
import AdminPanel from './pages/AdminPanel';                                     import MyActivity from './pages/MyActivity';
import Categories from './pages/Categories';                                     import Search from './pages/Search';
import Notifications from './pages/Notifications';                               import AccountSettings from './pages/AccountSettings';
import Analytics from './pages/Analytics';                                       import ThreadDetail from './pages/ThreadDetail';
import UserProfile from './pages/UserProfile';
import { useAuth } from './context/AuthContext';                                 import LoginRegisterModal from './components/LoginRegisterModal';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  return user ? <>{children}</> : <Navigate to="/" />;
}
function AdminProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();                                                      return user && user.role === "admin" ? <>{children}</> : <Navigate to="/" />;
}                                                                                
export default function App() {                                                    const [authModalOpen, setAuthModalOpen] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);                       const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
                                                                                   React.useEffect(() => {
    document.body.style.overflow = (isSidebarOpen || authModalOpen) ? "hidden" : "";                                                                                  return () => { document.body.style.overflow = ""; };
  }, [isSidebarOpen, authModalOpen]);                                            
  return (                                                                           <Router>
      <div className="min-h-screen flex flex-col bg-gray-50">                            <Header
          onAuthClick={() => setAuthModalOpen(true)}
          onMenuToggle={() => setIsSidebarOpen(!isSidebarOpen)}
        />
        <div className="flex flex-1 relative">
          <Sidebar
            isOpen={isSidebarOpen}
            onCloseSidebar={() => setIsSidebarOpen(false)}
            selectedCategory={selectedCategory}
            onCategorySelect={setSelectedCategory}
          />
          {isSidebarOpen && (
            <div
              className="fixed inset-0 bg-black bg-opacity-50 z-30 md:hidden"
              onClick={() => setIsSidebarOpen(false)}
            />
          )}
          <main className="flex-1 min-h-screen p-4 md:p-6">
            <Routes>
              <Route path="/" element={
                <ForumHome
                  selectedCategory={selectedCategory}
                  onCategorySelect={setSelectedCategory}
                />
              } />
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/profile"
                element={
                  <ProtectedRoute>
                    <Profile />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/my-activity"
                element={
                  <ProtectedRoute>
                    <MyActivity />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/categories"
                element={
                  <ProtectedRoute>
                    <Categories />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/search"
                element={
                  <ProtectedRoute>
                    <Search />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/notifications"
                element={
                  <ProtectedRoute>                                                                   <Notifications />
                  </ProtectedRoute>                                                              }
              />                                                                               <Route
                path="/settings"                                                                 element={
                  <ProtectedRoute>                                                                   <AccountSettings />
                  </ProtectedRoute>                                                              }
              />                                                                               <Route
                path="/analytics"                                                                element={
                  <AdminProtectedRoute>
                    <Analytics />
                  </AdminProtectedRoute>
                }
              />                                                                               <Route
                path="/admin"                                                                    element={
                  <AdminProtectedRoute>                                                              <AdminPanel />
                  </AdminProtectedRoute>                                                         }
              />                                                                               <Route
                path="/thread/:threadId"                                                         element={
                  <ProtectedRoute>                                                                   <ThreadDetail />
                  </ProtectedRoute>                                                              }
              />
              <Route
                path="/profile/:username"
                element={
                  <ProtectedRoute>                                                                   <UserProfile />
                  </ProtectedRoute>                                                              }
              />                                                                               <Route path="*" element={<Navigate to="/" />} />
            </Routes>                                                                      </main>
        </div>                                                                           <LoginRegisterModal
          isOpen={authModalOpen}                                                           onClose={() => setAuthModalOpen(false)}
        />                                                                             </div>
    </Router>                                                                      );
                              }
