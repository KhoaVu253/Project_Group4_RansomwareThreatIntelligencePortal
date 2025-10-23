import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';

import NavBar from './components/NavBar';
import AuthPage from './components/AuthPage';
import Dashboard from './pages/Dashboard';
import ScanPage from './pages/ScanPage';
import HistoryPage from './pages/HistoryPage';
import ProfilePage from './pages/ProfilePage';
import RansomwareLanding from './pages/RansomwareLanding';

import './App.css';

const AUTH_STORAGE_KEY = 'vt-auth-user';
const EMPTY_QUERY = { indicator: '', type: '', display: '' };
const MAX_POLL_ATTEMPTS = 120;
const POLL_INTERVAL_MS = 6000;
const HISTORY_STORAGE_PREFIX = 'vt-history-';
const PROFILE_STORAGE_PREFIX = 'vt-profile-';
const HISTORY_LIMIT = 150;

const createHistoryStorageKey = (user) => {
  if (!user) return null;
  const identifier = (user.email || user.username || user.fullName || '').toLowerCase();
  if (!identifier) return null;
  return `${HISTORY_STORAGE_PREFIX}${identifier}`;
};

const createProfileStorageKey = (user) => {
  if (!user) return null;
  const identifier = (user.email || user.username || user.fullName || '').toLowerCase();
  if (!identifier) return null;
  return `${PROFILE_STORAGE_PREFIX}${identifier}`;
};

const toNumber = (value) => (Number.isFinite(value) ? value : parseInt(value, 10) || 0);

const buildSummary = (entityType, vtPayload) => {
  if (!vtPayload || !vtPayload.data) return null;
  const attributes = vtPayload.data.attributes || {};
  const normalizedType = entityType === 'file' || entityType === 'hash' ? 'file' : entityType;

  if (normalizedType === 'file') {
    const summaryStats = attributes.results_summary?.stats || attributes.last_analysis_stats;
    if (!summaryStats) return null;
    const malicious = toNumber(summaryStats.malicious);
    const suspicious = toNumber(summaryStats.suspicious);
    const harmless = toNumber(summaryStats.harmless);
    const undetected = toNumber(summaryStats.undetected);
    const total = malicious + suspicious + harmless + undetected;
    if (total <= 0) return null;
    if (malicious > 0) {
      return `${malicious}/${total} security vendors flagged this object as malicious.`;
    }
    if (suspicious > 0) {
      return `${suspicious}/${total} security vendors flagged this object as suspicious.`;
    }
    return 'No security vendors flagged this object as malicious.';
  }

  if (normalizedType === 'url') {
    const stats = attributes.last_analysis_stats;
    if (stats) {
      const malicious = toNumber(stats.malicious);
      const suspicious = toNumber(stats.suspicious);
      const harmless = toNumber(stats.harmless);
      const undetected = toNumber(stats.undetected);
      const total = malicious + suspicious + harmless + undetected;
      if (total > 0) {
        if (malicious > 0) {
          return `${malicious}/${total} security vendors flagged this URL as malicious.`;
        }
        if (suspicious > 0) {
          return `${suspicious}/${total} security vendors flagged this URL as suspicious.`;
        }
        return 'No security vendors flagged this URL as malicious.';
      }
    }
    const categories = attributes.categories || {};
    const maliciousVendors = Object.entries(categories).filter(
      ([, verdict]) => verdict && verdict.toLowerCase().includes('malicious')
    );
    if (maliciousVendors.length > 0) {
      return `${maliciousVendors.length} sources flagged this URL as containing malicious content.`;
    }
    return 'No sources have flagged this URL as malicious.';
  }

  if (normalizedType === 'domain' || normalizedType === 'ip_address') {
    const stats = attributes.last_analysis_stats;
    if (stats) {
      const malicious = toNumber(stats.malicious);
      const suspicious = toNumber(stats.suspicious);
      const harmless = toNumber(stats.harmless);
      const undetected = toNumber(stats.undetected);
      const total = malicious + suspicious + harmless + undetected;
      if (total > 0) {
        if (malicious > 0) {
          return `${malicious}/${total} security vendors flagged this object as malicious.`;
        }
        if (suspicious > 0) {
          return `${suspicious}/${total} security vendors flagged this object as suspicious.`;
        }
        return 'No security vendors flagged this object as malicious.';
      }
    }
  }

  return null;
};

const AuthenticatedApp = ({
  user,
  onLogout,
  metrics,
  highlightCards,
  isLoading,
  onLookupSubmit,
  onFileUpload,
  onUrlSubmit,
  onClear,
  response,
  error,
  activeQuery,
  analysisStatus,
  progressPercent,
  historyEntries,
  onReanalyzeHistoryEntry,
  onClearHistory,
  profile,
  onUpdateProfile,
  onRetry,
}) => {
  const navigate = useNavigate();
  const consoleSectionRef = useRef(null);

  const handleScrollToConsole = () => {
    if (consoleSectionRef.current) {
      consoleSectionRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  const handleAnalyzeAndRedirect = ({ indicator, type }) => {
    if (type === 'url') {
      onUrlSubmit(indicator);
    } else {
      onLookupSubmit({ indicator, type });
    }
    navigate('/scan');
  };

  const handleFileUploadAndRedirect = (file) => {
    onFileUpload(file);
    navigate('/scan');
  };

  const handleBackToDashboard = () => {
    navigate('/');
  };

  const handleNavigateHistory = () => {
    navigate('/history');
  };

  const handleNavigateProfile = () => {
    navigate('/profile');
  };

  const handleReanalyzeFromHistory = (entry) => {
    if (!entry) return;
    onReanalyzeHistoryEntry(entry);
    navigate('/scan');
  };

  const handleRetry = () => {
    onRetry();
  };

  return (
    <div className="App min-vh-100 bg-dark text-light position-relative overflow-hidden">
      <div className="app-background">
        <span className="app-aurora aurora-1" />
        <span className="app-aurora aurora-2" />
        <span className="app-noise" />
      </div>

      <NavBar
        user={user}
        profile={profile}
        onLogout={onLogout}
        onNavigateHistory={handleNavigateHistory}
        onNavigateProfile={handleNavigateProfile}
      />

      <Routes>
        <Route
          path="/"
          element={
            <Dashboard
              metrics={metrics}
              highlightCards={highlightCards}
              onAnalyze={handleAnalyzeAndRedirect}
              onFileUpload={handleFileUploadAndRedirect}
              onClear={onClear}
              isLoading={isLoading}
              onScrollToConsole={handleScrollToConsole}
              consoleRef={consoleSectionRef}
            />
          }
        />
        <Route
          path="/scan"
          element={
            <ScanPage
              response={response}
              error={error}
              isLoading={isLoading}
              activeQuery={activeQuery}
              analysisStatus={analysisStatus}
              progressPercent={progressPercent}
              onBack={handleBackToDashboard}
              onRetry={handleRetry}
            />
          }
        />
        <Route
          path="/history"
          element={
            <HistoryPage
              entries={historyEntries}
              onReanalyze={handleReanalyzeFromHistory}
              onClear={onClearHistory}
            />
          }
        />
        <Route
          path="/profile"
          element={
            <ProfilePage
              user={user}
              profile={profile}
              historyEntries={historyEntries}
              onUpdateProfile={onUpdateProfile}
              onNavigateHistory={handleNavigateHistory}
            />
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
};

function App() {
  const [response, setResponse] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [activeQuery, setActiveQuery] = useState(EMPTY_QUERY);
  const [analysisStatus, setAnalysisStatus] = useState('idle');
  const [analysisId, setAnalysisId] = useState(null);
  const [progressPercent, setProgressPercent] = useState(0);
  const [historyEntries, setHistoryEntries] = useState([]);
  const [profile, setProfile] = useState({
    displayName: '',
    email: '',
    organization: '',
    role: '',
    bio: ''
  });
  const pollingTimeoutRef = useRef(null);
  const backendBaseUrl = useMemo(() => {
    const raw = import.meta.env.VITE_BACKEND_URL || '';
    return raw.endsWith('/') ? raw.slice(0, -1) : raw;
  }, []);

  const [currentUser, setCurrentUser] = useState(() => {
    if (typeof window === 'undefined') return null;
    try {
      const stored = window.localStorage.getItem(AUTH_STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch (storageError) {
      console.error('Failed to parse stored user', storageError);
      return null;
    }
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (currentUser) {
      window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(currentUser));
    } else {
      window.localStorage.removeItem(AUTH_STORAGE_KEY);
    }
  }, [currentUser]);

  const refreshHistoryFromServer = useCallback(
    async (email) => {
      if (!email) return;
      try {
        const endpoint = backendBaseUrl ? `${backendBaseUrl}/api/history` : '/api/history';
        const res = await axios.get(endpoint, {
          params: { email, limit: HISTORY_LIMIT },
        });
        const serverHistory = Array.isArray(res.data?.history) ? res.data.history : [];
        setHistoryEntries(serverHistory);
      } catch (err) {
        console.error('Failed to fetch history from server', err);
      }
    },
    [backendBaseUrl]
  );

  useEffect(() => {
    if (!currentUser) {
      setHistoryEntries([]);
      setProfile(null);
      return;
    }
    refreshHistoryFromServer(currentUser.email);

    const profileKey = createProfileStorageKey(currentUser);
    if (!profileKey) {
      setProfile({
        displayName: currentUser.fullName || currentUser.email || 'Người dùng',
        email: currentUser.email || '',
        organization: '',
        role: '',
        bio: '',
      });
      return;
    }

    try {
      const rawProfile = window.localStorage.getItem(profileKey);
      if (rawProfile) {
        setProfile(JSON.parse(rawProfile));
      } else {
        setProfile({
          displayName: currentUser.fullName || currentUser.email || 'Người dùng',
          email: currentUser.email || '',
          organization: '',
          role: '',
          bio: '',
        });
      }
    } catch (err) {
      console.error('Failed to load profile from storage', err);
      setProfile({
        displayName: currentUser.fullName || currentUser.email || 'Người dùng',
        email: currentUser.email || '',
        organization: '',
        role: '',
        bio: '',
      });
    }
  }, [currentUser, refreshHistoryFromServer]);

  useEffect(() => {
    if (!currentUser) return;
    const profileKey = createProfileStorageKey(currentUser);
    if (!profileKey) return;
    try {
      if (!profile) {
        window.localStorage.removeItem(profileKey);
      } else {
        window.localStorage.setItem(profileKey, JSON.stringify(profile));
      }
    } catch (err) {
      console.error('Failed to persist profile data', err);
    }
  }, [profile, currentUser]);

  const clearPolling = useCallback(() => {
    if (pollingTimeoutRef.current) {
      clearTimeout(pollingTimeoutRef.current);
      pollingTimeoutRef.current = null;
    }
  }, []);

  useEffect(() => () => clearPolling(), [clearPolling]);

  const metrics = useMemo(
    () => [
      { label: 'Scanning Engines', value: '70+', caption: 'Multi-engine matching' },
      { label: 'Daily Analysis', value: '1.8M', caption: 'Global malware samples' },
      { label: 'Response Time', value: '< 2s', caption: 'Instant VirusTotal proxy' },
    ],
    []
  );

  const highlightCards = useMemo(
    () => [
      {
        icon: 'ShieldCheck',
        title: 'Multi-Layer Defense',
        description: 'Combines signatures, sandboxes, and threat intelligence to identify ransomware more accurately.',
      },
      {
        icon: 'LightningChargeFill',
        title: 'Fast Workflow',
        description: 'Automates hashing and queries, helping SOC teams save time on incident response.',
      },
      {
        icon: 'Globe2',
        title: 'Global Scope',
        description: 'Synchronizes data from international partners to detect emerging campaigns.',
      },
      {
        icon: 'BarChartFill',
        title: 'Analytics Insights',
        description: 'Observe engine-specific details and threat statistics in a single dashboard.',
      },
    ],
    []
  );

  const persistHistoryEntry = useCallback(
    (responseData, context) => {
      if (!currentUser) return;
      const attributes = responseData?.data?.attributes;
      if (!attributes) return;
      const stats = attributes.last_analysis_stats || {};
      const malicious = toNumber(stats.malicious);
      const suspicious = toNumber(stats.suspicious);
      const harmless = toNumber(stats.harmless);
      const undetected = toNumber(stats.undetected);
      const total = malicious + suspicious + harmless + undetected;
      const entry = {
        id:
          typeof crypto !== 'undefined' && crypto.randomUUID
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        indicator: context?.indicator || '',
        display: context?.display || context?.indicator || '',
        type: context?.type || '',
        summary: context?.summary || buildSummary(context?.type, responseData) || '',
        malicious,
        suspicious,
        harmless,
        undetected,
        total,
        savedAt: new Date().toISOString(),
        response: responseData,
      };

      setHistoryEntries((prev) => {
        const next = [entry, ...prev].slice(0, HISTORY_LIMIT);
        return next;
      });
      if (currentUser?.email) {
        refreshHistoryFromServer(currentUser.email);
      }
    },
    [currentUser, refreshHistoryFromServer]
  );

  const handleAnalysisSubmit = useCallback(async ({ indicator, type }, options = {}) => {
    const trimmedIndicator = indicator?.trim?.() ?? '';
    if (!trimmedIndicator) return;

    setAnalysisId(null);
    setAnalysisStatus(options.statusOverride || 'lookup');
    setActiveQuery({
      indicator: trimmedIndicator,
      type,
      display: options.displayLabel ?? trimmedIndicator,
      summary: options.summaryOverride || null,
    });
    setProgressPercent(options.startProgress ?? 45);
    setIsLoading(true);
    setError(null);
    setResponse(null);

    try {
      const res = await axios.post(`${backendBaseUrl}/api/analyze`, {
        value: trimmedIndicator,
        type,
        user_email: currentUser?.email || null,
        user_full_name: currentUser?.fullName || currentUser?.displayName || null,
        display_value: options.displayLabel ?? trimmedIndicator,
      });
      setResponse(res.data);
      setAnalysisStatus('completed');
      setProgressPercent(options.successProgress ?? 100);

      const computedSummary = buildSummary(type, res.data);
      const summaryToUse = options.summaryOverride || computedSummary || null;
      if (summaryToUse) {
        setActiveQuery((prev) => ({
          ...prev,
          summary: summaryToUse,
        }));
      }
      if (options.preventSave !== true) {
        persistHistoryEntry(res.data, {
          indicator: trimmedIndicator,
          display: options.displayLabel ?? trimmedIndicator,
          type,
          summary: summaryToUse,
        });
      }
    } catch (err) {
      const errorData = err.response ? err.response.data : { error: 'An unexpected error occurred' };
      setError(errorData);
      setAnalysisStatus('error');
      setProgressPercent((prev) => (prev >= 95 ? prev : 95));
      console.error(errorData);
    } finally {
      setIsLoading(false);
    }
  }, [backendBaseUrl, currentUser, persistHistoryEntry]);

  const pollAnalysisStatus = useCallback(
    async (id, options, attempt = 0) => {
      try {
        const res = await axios.get(`${backendBaseUrl}/api/analysis/${id}`);
        const vtData = res.data;
        const status = vtData?.data?.attributes?.status || 'unknown';
        setAnalysisStatus(status);

        if (status === 'completed') {
          clearPolling();
          setAnalysisId(null);
          setProgressPercent((prev) => (prev >= 92 ? prev : 92));

          let followUpIndicator = options.followUpIndicator;
          let displayLabel = options.displayLabel;
          const summaryFromAnalysis = buildSummary(
            options.followUpType || options.initialType || activeQuery.type,
            vtData
          );

          if (options.followUpType === 'file') {
            const fileInfo =
              vtData?.meta?.file_info ||
              vtData?.data?.meta?.file_info ||
              vtData?.data?.attributes?.file_info ||
              {};
            followUpIndicator = followUpIndicator || fileInfo.sha256 || fileInfo.sha1 || fileInfo.md5;
            displayLabel = displayLabel || fileInfo.name || followUpIndicator;
          } else if (options.followUpType === 'url') {
            const urlInfo = vtData?.meta?.url_info || vtData?.data?.meta?.url_info || {};
            displayLabel = displayLabel || urlInfo.url || followUpIndicator;
          }
          options.summaryOverride = summaryFromAnalysis || options.summaryOverride || null;

          if (followUpIndicator) {
            await handleAnalysisSubmit(
              { indicator: followUpIndicator, type: options.followUpType },
              {
                displayLabel,
                statusOverride: 'lookup',
                startProgress: 92,
                successProgress: 100,
                summaryOverride: options.summaryOverride,
              }
            );
          } else {
            // Fallback: surface raw analysis data
            setIsLoading(false);
            setResponse(vtData);
            setAnalysisStatus('completed');
            setProgressPercent(100);
            const fallbackSummary =
              summaryFromAnalysis || buildSummary(options.initialType || activeQuery.type, vtData) || options.summaryOverride;
            if (fallbackSummary) {
              setActiveQuery((prev) => ({
                ...prev,
                summary: fallbackSummary,
              }));
            }
            if (options.preventSave !== true) {
              persistHistoryEntry(vtData, {
                indicator:
                  followUpIndicator ||
                  options.followUpIndicator ||
                  options.initialIndicator ||
                  activeQuery.indicator ||
                  '',
                display:
                  displayLabel ||
                  options.displayLabel ||
                  options.initialDisplay ||
                  activeQuery.display ||
                  followUpIndicator ||
                  '',
                type: options.followUpType || options.initialType || activeQuery.type,
                summary: fallbackSummary,
              });
            }
          }
          return;
        }

        if (['queued', 'running', 'in-progress', 'pending', 'analyzing'].includes(status) && attempt < MAX_POLL_ATTEMPTS) {
          const progressForAttempt = Math.min(
            95,
            25 + Math.round(((attempt + 1) / MAX_POLL_ATTEMPTS) * 60)
          );
          setProgressPercent((prev) => Math.max(prev, progressForAttempt));
          pollingTimeoutRef.current = setTimeout(() => {
            pollAnalysisStatus(id, options, attempt + 1);
          }, POLL_INTERVAL_MS);
          return;
        }

        if (attempt >= MAX_POLL_ATTEMPTS) {
          clearPolling();
          setIsLoading(false);
          setError({ error: { message: 'Timeout chờ kết quả từ VirusTotal' } });
          setAnalysisStatus('timeout');
          setProgressPercent(100);
          return;
        }

        // Any other status is considered error
        clearPolling();
        setIsLoading(false);
        setError({ error: { message: `VirusTotal trả về trạng thái ${status}` } });
        setAnalysisStatus('error');
        setProgressPercent(100);
    } catch (err) {
      console.error('Polling analysis failed', err);
      if (attempt >= MAX_POLL_ATTEMPTS) {
        clearPolling();
        const errorData = err.response ? err.response.data : { error: { message: String(err) } };
        setError(errorData);
        setIsLoading(false);
        setAnalysisStatus('error');
        setProgressPercent(100);
        return;
      }
      if (err.response?.status === 429) {
        const retryAfter = Number(err.response.headers?.['retry-after']) || 15;
        const delay = Math.min(retryAfter * 1000, POLL_INTERVAL_MS * 5);
        pollingTimeoutRef.current = setTimeout(() => {
          pollAnalysisStatus(id, options, attempt + 1);
        }, delay);
        return;
      }
      const fallbackProgress = Math.min(
        95,
        25 + Math.round(((attempt + 1) / MAX_POLL_ATTEMPTS) * 60)
      );
      setProgressPercent((prev) => Math.max(prev, fallbackProgress));
        pollingTimeoutRef.current = setTimeout(() => {
          pollAnalysisStatus(id, options, attempt + 1);
        }, POLL_INTERVAL_MS);
      }
    },
    [backendBaseUrl, clearPolling, handleAnalysisSubmit, persistHistoryEntry]
  );

  const handleFileUpload = useCallback(
    async (file) => {
      if (!file) return;
      clearPolling();

      setActiveQuery({ indicator: '', type: 'file', display: file.name });
      setProgressPercent(5);
      setIsLoading(true);
      setError(null);
      setResponse(null);
      setAnalysisStatus('uploading');

      const formData = new FormData();
      formData.append('file', file);
      if (currentUser?.email) {
        formData.append('user_email', currentUser.email);
      }
      if (currentUser?.fullName) {
        formData.append('user_full_name', currentUser.fullName);
      } else if (currentUser?.displayName) {
        formData.append('user_full_name', currentUser.displayName);
      }

      try {
        const res = await axios.post(`${backendBaseUrl}/api/upload-file`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
        const newAnalysisId = res.data?.analysis_id;
        if (!newAnalysisId) {
          throw new Error('VirusTotal không trả về analysis_id');
        }

        setAnalysisId(newAnalysisId);
        setAnalysisStatus('polling');
        setProgressPercent(25);
        pollAnalysisStatus(newAnalysisId, {
          followUpType: 'file',
          displayLabel: file.name,
          initialType: 'file',
          initialIndicator: '',
          initialDisplay: file.name,
        });
      } catch (err) {
        clearPolling();
        const errorData = err.response ? err.response.data : { error: { message: String(err) } };
        setError(errorData);
        setIsLoading(false);
        setAnalysisStatus('error');
        setProgressPercent(100);
      }
    },
    [backendBaseUrl, clearPolling, currentUser, pollAnalysisStatus]
  );

  const handleUrlSubmit = useCallback(
    async (url) => {
      const trimmedUrl = url?.trim?.();
      if (!trimmedUrl) return;
      clearPolling();

      setActiveQuery({ indicator: trimmedUrl, type: 'url', display: trimmedUrl });
      setProgressPercent(5);
      setIsLoading(true);
      setError(null);
      setResponse(null);
      setAnalysisStatus('uploading');

      try {
        const res = await axios.post(`${backendBaseUrl}/api/upload-url`, {
          url: trimmedUrl,
          user_email: currentUser?.email || null,
          user_full_name: currentUser?.fullName || currentUser?.displayName || null,
        });
        const newAnalysisId = res.data?.analysis_id;
        if (!newAnalysisId) {
          throw new Error('VirusTotal không trả về analysis_id cho URL');
        }

        setAnalysisId(newAnalysisId);
        setAnalysisStatus('polling');
        setProgressPercent(25);
        pollAnalysisStatus(newAnalysisId, {
          followUpType: 'url',
          followUpIndicator: trimmedUrl,
          displayLabel: trimmedUrl,
          initialType: 'url',
          initialIndicator: trimmedUrl,
          initialDisplay: trimmedUrl,
        });
      } catch (err) {
        clearPolling();
        const errorData = err.response ? err.response.data : { error: { message: String(err) } };
        setError(errorData);
        setIsLoading(false);
        setAnalysisStatus('error');
        setProgressPercent(100);
      }
    },
    [backendBaseUrl, clearPolling, currentUser, pollAnalysisStatus]
  );

  const handleClear = useCallback(() => {
    clearPolling();
    setResponse(null);
    setError(null);
    setActiveQuery(EMPTY_QUERY);
    setAnalysisStatus('idle');
    setAnalysisId(null);
    setProgressPercent(0);
  }, [clearPolling]);

  const handleAuthSuccess = (user) => {
    setCurrentUser(user);
  };

  const handleLogout = () => {
    // Ask for confirmation before logging out
    const confirmLogout = window.confirm('Are you sure you want to logout?');
    
    if (!confirmLogout) {
      return; // User cancelled logout
    }
    
    // Clear all scan data and polling
    handleClear();
    
    // Remove user data from localStorage first (before clearing state)
    if (currentUser) {
      const historyKey = createHistoryStorageKey(currentUser);
      const profileKey = createProfileStorageKey(currentUser);
      
      if (historyKey) {
        localStorage.removeItem(historyKey);
      }
      if (profileKey) {
        localStorage.removeItem(profileKey);
      }
    }
    
    // Remove current user from localStorage
    localStorage.removeItem('currentUser');
    
    // Clear all state
    setCurrentUser(null);
    setProfile(null);
    setHistoryEntries([]);
    
    // Show success message
    console.log('✓ Logged out successfully');
  };

  const handleClearHistory = useCallback(async () => {
    if (!currentUser?.email) {
      setHistoryEntries([]);
      return;
    }
    setHistoryEntries([]);
    try {
      const endpoint = backendBaseUrl ? `${backendBaseUrl}/api/history` : '/api/history';
      await axios.delete(endpoint, {
        params: { email: currentUser.email },
      });
      refreshHistoryFromServer(currentUser.email);
    } catch (err) {
      console.error('Failed to clear history on server', err);
    }
  }, [backendBaseUrl, currentUser, refreshHistoryFromServer]);

  const handleUpdateProfile = useCallback(
    (updates) => {
      if (!currentUser) return;
      setProfile((prev) => ({
        ...prev,
        ...updates,
        email: prev?.email || currentUser.email || '',
      }));
    },
    [currentUser]
  );

  const handleRetry = () => {
    if (analysisId) {
      setProgressPercent((prev) => (prev > 25 ? prev : 25));
      pollAnalysisStatus(analysisId, {
        followUpType: activeQuery.type || 'file',
        followUpIndicator: activeQuery.indicator || undefined,
        displayLabel: activeQuery.display || undefined,
        initialType: activeQuery.type || 'file',
        initialIndicator: activeQuery.indicator || undefined,
        initialDisplay: activeQuery.display || undefined,
      });
      return;
    }

    if (activeQuery?.indicator && activeQuery?.type) {
      handleAnalysisSubmit(
        { indicator: activeQuery.indicator, type: activeQuery.type },
        { displayLabel: activeQuery.display || activeQuery.indicator }
      );
    }
  };

  const handleReanalyzeHistoryEntry = useCallback(
    (entry) => {
      if (!entry) return;
      handleAnalysisSubmit(
        { indicator: entry.indicator, type: entry.type },
        { displayLabel: entry.display || entry.indicator, summaryOverride: entry.summary }
      );
    },
    [handleAnalysisSubmit]
  );

  const isAuthenticated = Boolean(currentUser);

  if (!isAuthenticated) {
    return (
      <div className="App min-vh-100 bg-dark text-light position-relative overflow-hidden">
        <div className="app-background">
          <span className="app-aurora aurora-1" />
          <span className="app-aurora aurora-2" />
          <span className="app-noise" />
        </div>
        <Routes>
          <Route
            path="/"
            element={<RansomwareLanding />}
          />
          <Route path="/login" element={<AuthPage onSuccess={handleAuthSuccess} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    );
  }

  return (
    <AuthenticatedApp
      user={currentUser}
      onLogout={handleLogout}
      metrics={metrics}
      highlightCards={highlightCards}
      isLoading={isLoading}
      onLookupSubmit={handleAnalysisSubmit}
      onFileUpload={handleFileUpload}
      onUrlSubmit={handleUrlSubmit}
      onClear={handleClear}
      response={response}
      error={error}
      activeQuery={activeQuery}
      analysisStatus={analysisStatus}
      progressPercent={progressPercent}
      historyEntries={historyEntries}
      onReanalyzeHistoryEntry={handleReanalyzeHistoryEntry}
      onClearHistory={handleClearHistory}
      profile={profile}
      onUpdateProfile={handleUpdateProfile}
      onRetry={handleRetry}
    />
  );
}

export default App;
