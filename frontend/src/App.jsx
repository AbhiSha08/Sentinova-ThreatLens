import React, { useState } from 'react';
import Navbar from './components/Navbar';
import ExecutiveView from './pages/ExecutiveView';
import AnalystView from './pages/AnalystView';
import IndicatorDrawer from './components/IndicatorDrawer';
import BulkLookupModal from './components/BulkLookupModal';
import FeedStatusModal from './components/FeedStatusModal';

export default function App() {
  const [activeView, setActiveView] = useState('executive');
  const [selectedIndicator, setSelectedIndicator] = useState(null);
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
  const [isFeedsModalOpen, setIsFeedsModalOpen] = useState(false);
  const [analystFilters, setAnalystFilters] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const handleNavigateToAnalyst = (filters = {}) => {
    setAnalystFilters(filters);
    setActiveView('analyst');
  };

  const handleSyncCompleted = () => {
    setRefreshKey((prev) => prev + 1);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      
      {/* Top Cyber Navigation Bar */}
      <Navbar
        activeView={activeView}
        setActiveView={setActiveView}
        onSyncCompleted={handleSyncCompleted}
        onOpenFeedsModal={() => setIsFeedsModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeView === 'executive' ? (
          <ExecutiveView
            key={`exec-${refreshKey}`}
            onNavigateToAnalyst={handleNavigateToAnalyst}
            onInspectIndicator={(ind) => setSelectedIndicator(ind)}
          />
        ) : (
          <AnalystView
            key={`analyst-${refreshKey}`}
            initialFilters={analystFilters}
            onInspectIndicator={(ind) => setSelectedIndicator(ind)}
            onOpenBulkModal={() => setIsBulkModalOpen(true)}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs font-mono text-slate-500">
        <p>Sentinova ThreatLens Cyber Threat Intelligence Fusion Platform • Python 3.14 + FastAPI + React 18 + Tailwind CSS</p>
      </footer>

      {/* Slide-over IOC Enrichment Drawer */}
      <IndicatorDrawer
        indicator={selectedIndicator}
        onClose={() => setSelectedIndicator(null)}
        onSelectIndicator={(ind) => setSelectedIndicator(ind)}
      />

      {/* Bulk IOC Triage Modal */}
      <BulkLookupModal
        isOpen={isBulkModalOpen}
        onClose={() => setIsBulkModalOpen(false)}
        onInspectIndicator={(ind) => setSelectedIndicator(ind)}
      />

      {/* Feed Telemetry Health Modal */}
      <FeedStatusModal
        isOpen={isFeedsModalOpen}
        onClose={() => setIsFeedsModalOpen(false)}
        onSyncCompleted={handleSyncCompleted}
      />

    </div>
  );
}
