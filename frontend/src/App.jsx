import React, { useEffect, useState } from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import TechStackSection from './components/TechStackSection';
import WebCheckWhatWebSection from './components/WebCheckWhatWebSection';
import OutputFeedSection from './components/OutputFeedSection';
import SeoAuditSection from './components/seo/SeoAuditSection';
import CompetitiveSection from './components/competitive/CompetitiveSection';
import Features from './components/Features';
import Portfolio from './components/Portfolio';
import Integrations from './components/Integrations';
import HowItWorks from './components/HowItWorks';
import Comparison from './components/Comparison';
import ExtensionPromoSection from './components/ExtensionPromoSection';
import FinalCTA from './components/FinalCTA';
import Footer from './components/Footer';
import ExtensionPromoModal from './components/ExtensionPromoModal';
import { useScanner, useScanHistory } from './hooks/useScanner';
import { useSeoScanner } from './hooks/useSeoScanner';
import { useTechStack } from './hooks/useTechStack';

export default function App() {
  const [extensionOpen, setExtensionOpen] = useState(false);
  const [reconReport, setReconReport] = useState(null);
  const scanner = useScanner();
  const techStack = useTechStack();
  const seoScanner = useSeoScanner();
  const { history, fetchHistory } = useScanHistory();

  // Load history on mount
  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Refresh history whenever a scan finishes
  useEffect(() => {
    if (scanner.status === 'done') {
      fetchHistory();
    }
  }, [scanner.status, fetchHistory]);

  const handleScrollToScanner = () => {
    const el = document.getElementById('scanner');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleScrollToSeo = () => {
    const el = document.getElementById('seo-audit');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleScanUrl = (url, options = {}) => {
    const { includeSecurity = true, includeTechStack = true, includeSeo = true } = options;
    
    // Automatically trigger deep domain reconnaissance
    fetch(`/api/domain/recon?url=${encodeURIComponent(url)}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((json) => {
        if (json?.data || json) setReconReport(json.data || json);
      })
      .catch(() => {});

    if (includeSecurity) {
      scanner.scan(url, options);
    } else {
      scanner.reset();
    }

    if (includeTechStack) {
      techStack.detect(url);
    } else {
      techStack.reset();
    }

    if (includeSeo) {
      seoScanner.audit(url);
    } else {
      seoScanner.reset();
    }

    handleScrollToScanner();
  };

  const handleSeoAudit = (url) => {
    seoScanner.audit(url);
    handleScrollToSeo();
  };

  return (
    <div className="min-h-screen bg-[#fffdf7] text-[#18181b] antialiased selection:bg-yellow-200 selection:text-black">
      <Navbar
        onScrollToScanner={handleScrollToScanner}
        onOpenExtension={() => setExtensionOpen(true)}
      />

      <Hero
        scannerState={scanner}
        techStackState={techStack}
        seoState={seoScanner}
        reconReport={reconReport || scanner.report?.domainRecon}
        onScan={handleScanUrl}
        onRescan={handleScanUrl}
      />

      {/* Autonomous Perimeter Intelligence & Asset Reconnaissance Section */}
      <WebCheckWhatWebSection
        initialDomain={scanner.report?.hostname || techStack.report?.hostname || 'github.com'}
        onReconUpdate={setReconReport}
        externalReconData={reconReport}
      />

      {/* Tech Stack & Hosting Infrastructure Intelligence Section */}
      <TechStackSection
        techStackState={techStack}
        initialUrl={scanner.report?.finalUrl || 'https://wordpress.org'}
      />

      {/* Real-Time Telemetry & Terminal Output Feed Section */}
      <OutputFeedSection
        scannerReport={scanner.report}
        scannerState={scanner}
        techStackReport={techStack.report}
        reconReport={reconReport || scanner.report?.domainRecon}
      />

      {/* Complete SEO & Lighthouse Performance Audit Section */}
      <SeoAuditSection
        seoState={seoScanner}
        onScan={handleScanUrl}
      />

      {/* AI Competitor Intelligence, SEO/GEO/AEO Comparison & Keyword Opportunity Engine */}
      <CompetitiveSection />

      <Features />

      <Portfolio
        history={history}
        onRescan={handleScanUrl}
      />

      <Integrations />

      <HowItWorks />

      <Comparison />

      <ExtensionPromoSection onOpenExtension={() => setExtensionOpen(true)} />

      <FinalCTA onScrollToScanner={handleScrollToScanner} />

      <Footer
        onOpenExtension={() => setExtensionOpen(true)}
      />

      {/* Interactive Chrome Extension Modal */}
      <ExtensionPromoModal
        isOpen={extensionOpen}
        onClose={() => setExtensionOpen(false)}
      />
    </div>
  );
}
