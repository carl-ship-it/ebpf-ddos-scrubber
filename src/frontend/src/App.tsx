import React, { lazy, Suspense } from 'react';
import { ConfigProvider, theme, Spin } from 'antd';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { darkTheme } from './styles/theme';
import { useRealtimeConnection } from './hooks/useStats';
import AppLayout from './components/Layout';

// Eager load Dashboard (primary page)
import Dashboard from './pages/Dashboard';

// Lazy load other pages
const ACLPage = lazy(() => import('./pages/ACL'));
const RateLimitPage = lazy(() => import('./pages/RateLimit'));
const EventsPage = lazy(() => import('./pages/Events'));
const SignaturesPage = lazy(() => import('./pages/Signatures'));
const SettingsPage = lazy(() => import('./pages/Settings'));
const GeoIPPage = lazy(() => import('./pages/GeoIP'));
const ReputationPage = lazy(() => import('./pages/Reputation'));
const EscalationPage = lazy(() => import('./pages/Escalation'));
const BaselinePage = lazy(() => import('./pages/Baseline'));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntel'));
const BGPPage = lazy(() => import('./pages/BGP'));
const ProtoValidationPage = lazy(() => import('./pages/ProtoValidation'));

const Loading = () => (
  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 200 }}>
    <Spin size="large" />
  </div>
);

const AppInner: React.FC = () => {
  useRealtimeConnection();

  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/acl" element={<ACLPage />} />
          <Route path="/rate-limit" element={<RateLimitPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/signatures" element={<SignaturesPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/geoip" element={<GeoIPPage />} />
          <Route path="/reputation" element={<ReputationPage />} />
          <Route path="/escalation" element={<EscalationPage />} />
          <Route path="/baseline" element={<BaselinePage />} />
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/bgp" element={<BGPPage />} />
          <Route path="/proto-validation" element={<ProtoValidationPage />} />
        </Route>
      </Routes>
    </Suspense>
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
