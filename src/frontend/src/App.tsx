import React from 'react';
import { ConfigProvider, theme } from 'antd';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { darkTheme } from './styles/theme';
import { useRealtimeConnection } from './hooks/useStats';
import AppLayout from './components/Layout';
import Dashboard from './pages/Dashboard';
import ACLPage from './pages/ACL';
import RateLimitPage from './pages/RateLimit';
import EventsPage from './pages/Events';
import SignaturesPage from './pages/Signatures';
import SettingsPage from './pages/Settings';

const AppInner: React.FC = () => {
  useRealtimeConnection();

  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/acl" element={<ACLPage />} />
        <Route path="/rate-limit" element={<RateLimitPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/signatures" element={<SignaturesPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
};

const App: React.FC = () => {
  return (
    <ConfigProvider
      theme={{
        ...darkTheme,
        algorithm: theme.darkAlgorithm,
      }}
    >
      <BrowserRouter>
        <AppInner />
      </BrowserRouter>
    </ConfigProvider>
  );
};

export default App;
