import React, { useEffect, useMemo, useRef, useState } from 'react';

function ScrollProgress({ progress }) {
  return (
    <div className="rl-progress" aria-hidden="true">
      <div className="rl-progress-track">
        <div
          className="rl-progress-bar"
          style={{ transform: `scaleY(${Math.min(Math.max(progress, 0), 1)})` }}
        />
      </div>
    </div>
  );
}

function ParticleBackground() {
  return (
    <div className="rl-particles" aria-hidden="true">
      {[...Array(30)].map((_, i) => (
        <div
          key={i}
          className="rl-particle"
          style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 15}s`,
            animationDuration: `${20 + Math.random() * 15}s`
          }}
        />
      ))}
    </div>
  );
}

function GlowCard({ children, className = '' }) {
  const cardRef = useRef(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  const handleMouseMove = (e) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    setMousePosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    });
  };

  return (
    <div
      ref={cardRef}
      className={`rl-glow-card ${className}`}
      onMouseMove={handleMouseMove}
      style={{
        '--mouse-x': `${mousePosition.x}px`,
        '--mouse-y': `${mousePosition.y}px`
      }}
    >
      <div className="rl-glow-card-effect" />
      <div className="rl-glow-card-content">
        {children}
      </div>
    </div>
  );
}

function ShieldIcon({ className }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      role="img"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M12 3.5l7 3v4.9c0 4.3-2.9 8.4-7 9.6-4.1-1.2-7-5.3-7-9.6V6.5l7-3z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="M9.5 12.2L11 13.7l3.5-3.6"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function AlertIcon({ className }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      role="img"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M12 3l9 16H3L12 3z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M12 9v5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
      <circle cx="12" cy="16.5" r="1.2" fill="currentColor" />
    </svg>
  );
}

function LockIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <rect
        x="5.5"
        y="10"
        width="13"
        height="10"
        rx="2"
        ry="2"
        stroke="currentColor"
        fill="none"
        strokeWidth="1.5"
      />
      <path
        d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <circle cx="12" cy="14.5" r="1.2" fill="currentColor" />
      <path d="M12 15.7v1.6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

function UploadIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M12 4.5v12"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
      <path
        d="M8.5 8.5L12 5l3.5 3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect
        x="5"
        y="13.5"
        width="14"
        height="6"
        rx="2"
        ry="2"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
      />
    </svg>
  );
}

function PulseIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M3 14h4l2.5-6 3.5 10 2.5-6h5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function HistoryIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <circle
        cx="12"
        cy="12"
        r="7.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path
        d="M12 9v4l2.5 1.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M5 12H3m18 0h-2"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

function ChartIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M5 19V9m7 10V5m7 14v-7"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      <path
        d="M4 19h16"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

function ArrowIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M6 12h12m-5-5 5 5-5 5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Reveal({ children, delay = 0 }) {
  const ref = useRef(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new IntersectionObserver(
      (entries, obs) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setVisible(true);
            obs.disconnect();
          }
        });
      },
      { threshold: 0.15 }
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={`rl-reveal ${visible ? 'rl-reveal--visible' : ''}`}
      style={{ transitionDelay: `${delay}ms` }}
    >
      {children}
    </div>
  );
}

function FeatureCard({ icon, title, desc }) {
  return (
    <GlowCard className="rl-card">
      <div className="rl-card-icon" aria-hidden="true">
        {icon}
      </div>
      <h3>{title}</h3>
      <p>{desc}</p>
    </GlowCard>
  );
}

function ArchStep({ index, title, desc }) {
  return (
    <div className="rl-arch-step">
      <span className="rl-arch-index" aria-hidden="true">
        {index.toString().padStart(2, '0')}
      </span>
      <div>
        <h4>{title}</h4>
        <p>{desc}</p>
      </div>
    </div>
  );
}

function Chip({ icon, title, note }) {
  return (
    <div className="rl-chip" role="group" aria-label={`${title} status`}>
      <span className="rl-chip-icon" aria-hidden="true">
        {icon}
      </span>
      <div className="rl-chip-text">
        <span className="rl-chip-title">{title}</span>
        <span className="rl-chip-note">{note}</span>
      </div>
    </div>
  );
}

function ProcessItem({ index, title, desc }) {
  return (
    <div className="rl-process-item">
      <span className="rl-process-badge" aria-hidden="true">
        {index}
      </span>
      <h3>{title}</h3>
      <p>{desc}</p>
    </div>
  );
}

function FAQItem({ question, answer, index }) {
  return (
    <details className="rl-faq-item">
      <summary>
        <span>{question}</span>
        <ArrowIcon className="rl-faq-arrow" />
      </summary>
      <div className="rl-faq-body" id={`faq-${index}`}>
        <p>{answer}</p>
      </div>
    </details>
  );
}

export default function RansomwareLanding({ onNavigateCommunity, onNavigateLogin }) {
  const containerRef = useRef(null);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const element = containerRef.current;
    if (!element) return;
    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = element;
      const ratio = scrollTop / Math.max(scrollHeight - clientHeight, 1);
      setProgress(ratio);
    };
    element.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => element.removeEventListener('scroll', handleScroll);
  }, []);

  const handleNavClick = (event, selector) => {
    event.preventDefault();
    const wrapper = containerRef.current;
    if (!wrapper) return;
    const target = wrapper.querySelector(selector);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      target.focus({ preventScroll: true });
    }
  };

  const featureCards = useMemo(
    () => [
      {
        icon: <ShieldIcon />,
        title: 'Unified IOC Console',
        desc: 'Analyze hashes, URLs, domains, and IP reputation in seconds with curated context pulled from VirusTotal and internal intel.',
      },
      {
        icon: <AlertIcon />,
        title: 'Detections That Matter',
        desc: 'Boost signal-to-noise with severity scoring, threat family matching, and highlight cards that explain the “so what”.',
      },
      {
        icon: <UploadIcon />,
        title: 'Frictionless Submissions',
        desc: 'Drop suspicious payloads or links, trigger sandboxing automatically, and watch status updates stream in near real time.',
      },
      {
        icon: <HistoryIcon />,
        title: 'Incident Memory',
        desc: 'Keep every investigation audit-ready with tamper-resistant history, CSV exports, and collaboration notes for the next responder.',
      },
    ],
    []
  );

  const archSteps = useMemo(
    () => [
      {
        title: 'Collect & Normalize',
        desc: 'Ingest submissions, passive DNS, and EDR signals into a single schema built for ransomware hunting.',
      },
      {
        title: 'Enrich & Score',
        desc: 'Fuse VirusTotal verdicts with heuristics, MITRE ATT&CK mapping, and internal tagging to prioritize what is weaponized.',
      },
      {
        title: 'Coordinate Response',
        desc: 'Push guided actions, evidence packages, and downstream tickets so containment and recovery stay in lockstep.',
      },
    ],
    []
  );

  const processFlow = useMemo(
    () => [
      {
        title: 'Discover',
        desc: 'Surface suspicious activity across email, endpoints, and cloud workloads with automated IOC capture.',
      },
      {
        title: 'Analyze',
        desc: 'Run multi-engine verdicts, detonation traces, and enrichment jobs to understand intent and blast radius.',
      },
      {
        title: 'Prioritize',
        desc: 'Score ransomware likelihood, map to MITRE techniques, and recommend the next best action for analysts.',
      },
      {
        title: 'Remediate',
        desc: 'Trigger containment playbooks, notify stakeholders, and document recovery steps without leaving the portal.',
      },
    ],
    []
  );

  const faqList = useMemo(
    () => [
      {
        question: 'How fast can we investigate a suspicious hash or URL?',
        answer: 'Most verdicts return in a few seconds thanks to cached VirusTotal intelligence and pre-built enrichment pipelines. File detonations continue in the background with status updates.',
      },
      {
        question: 'Do analysts need to install any agents?',
        answer: 'No agents required. Everything runs in the browser with secure API calls to your backend, so adoption is instant for responders and threat hunters.',
      },
      {
        question: 'Can it plug into our SIEM or SOAR stack?',
        answer: 'Yes. Use the REST endpoints to forward verified indicators, create tickets in your SOAR platform, or trigger playbooks via webhooks.',
      },
      {
        question: 'How is sensitive data protected?',
        answer: 'All submissions are encrypted in transit and at rest. Administrators can rotate API keys, enforce multi-factor access, and schedule automatic data purges.',
      },
      {
        question: 'Who typically uses the portal day to day?',
        answer: 'Security operations centers, incident responders, MDR providers, and threat intelligence teams who need a shared workspace for ransomware investigations.',
      },
      {
        question: 'Can we export evidence for audits?',
        answer: 'Absolutely. Every lookup has a preserved timeline and can be exported to CSV or JSON for regulators, legal teams, or tabletop exercises.',
      },
    ],
    []
  );

  const heroChips = useMemo(
    () => [
      { title: 'Threat Radar', note: 'Prioritized detections', icon: <ShieldIcon /> },
      { title: 'Live Verdicts', note: '70+ engine signals', icon: <AlertIcon /> },
      { title: 'Payload Watch', note: 'Encrypted file tracing', icon: <LockIcon /> },
      { title: 'Fast Submissions', note: 'One-click sandboxing', icon: <UploadIcon /> },
      { title: 'Telemetry Pulse', note: 'Behavioral analytics', icon: <PulseIcon /> },
      { title: 'Response Log', note: 'Auto-built timeline', icon: <HistoryIcon /> },
    ],
    []
  );

  return (
    <div className="rl-wrapper" ref={containerRef}>
      <ParticleBackground />
      <ScrollProgress progress={progress} />
      <main className="rl-main" tabIndex={-1}>
        <header className="rl-section rl-hero" id="hero">
          <div className="rl-ornament rl-ornament-left" aria-hidden="true" />
          <div className="rl-ornament rl-ornament-right" aria-hidden="true" />
          <div className="rl-hero-grid">
            <Reveal>
              <div className="rl-hero-copy">
                <div className="rl-hero-badge">
                  <span className="rl-badge-dot" />
                  <span>Modern Ransomware Defense</span>
                </div>
                <h1>
                  Outsmart <span className="rl-gradient-text">Ransomware</span>
                  <br />Before It Locks You Out
                </h1>
                <p className="rl-hero-desc">
                  Intelligent threat analysis with a workspace that detects the most dangerous encryptors, 
                  explains why they matter, and guides your team to act before downtime spreads.
                </p>
                <div className="rl-hero-actions">
                  <button
                    type="button"
                    className="rl-btn rl-btn-primary rl-btn-animated"
                    onClick={(event) => handleNavClick(event, '#features')}
                  >
                    <span>Explore Features</span>
                    <ArrowIcon className="rl-btn-icon" />
                  </button>
                  <button
                    type="button"
                    className="rl-btn rl-btn-secondary"
                    onClick={(event) => {
                      event.preventDefault();
                      if (onNavigateCommunity) {
                        onNavigateCommunity();
                      } else {
                        handleNavClick(event, '#faq');
                      }
                    }}
                  >
                    <span>Join Community</span>
                  </button>
                  <button
                    type="button"
                    className="rl-btn rl-btn-cta"
                    onClick={(event) => {
                      event.preventDefault();
                      onNavigateLogin?.();
                    }}
                  >
                    <span>Log in</span>
                    <ArrowIcon className="rl-btn-icon" />
                  </button>
                </div>
              </div>
            </Reveal>
            <Reveal delay={80}>
              <div className="rl-hero-visual" aria-label="Threat intelligence highlights">
                <div className="rl-hero-panel">
                  {heroChips.map((chip, idx) => (
                    <div key={chip.title} className="rl-chip rl-chip-animated" style={{ animationDelay: `${idx * 0.1}s` }}>
                      <span className="rl-chip-icon" aria-hidden="true">
                        {chip.icon}
                      </span>
                      <div className="rl-chip-text">
                        <span className="rl-chip-title">{chip.title}</span>
                        <span className="rl-chip-note">{chip.note}</span>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="rl-hero-stats">
                  <div className="rl-stat">
                    <div className="rl-stat-number">99.8%</div>
                    <div className="rl-stat-label">Detection Accuracy</div>
                  </div>
                  <div className="rl-stat">
                    <div className="rl-stat-number">&lt;3s</div>
                    <div className="rl-stat-label">Analysis Time</div>
                  </div>
                  <div className="rl-stat">
                    <div className="rl-stat-number">24/7</div>
                    <div className="rl-stat-label">Monitoring</div>
                  </div>
                </div>
              </div>
            </Reveal>
          </div>
        </header>

        <section className="rl-section" id="about" tabIndex={-1}>
          <div className="rl-section-inner">
            <Reveal>
              <h2 className="rl-section-title">Why Ransomware Response Needs A New Playbook</h2>
            </Reveal>
            <div className="rl-two-column">
              <Reveal delay={80}>
                <div className="rl-column-text">
                  <h3>What teams tell us</h3>
                  <ul>
                    <li>Ransomware crews pivot from phishing to privilege escalation in hours, leaving traditional SIEM dashboards behind.</li>
                    <li>Security leaders juggle hybrid infrastructure, cloud workloads, and supply-chain dependencies with limited shared context.</li>
                    <li>Incident responders need verdicts, next steps, and evidence in one place to collaborate under pressure.</li>
                  </ul>
                </div>
              </Reveal>
              <Reveal delay={160}>
                <div className="rl-threat-showcase">
                  <div className="rl-threat-header">
                    <h3 className="rl-threat-title">Notable Ransomware Attacks</h3>
                    <span className="rl-threat-subtitle">Real-world threats that changed cybersecurity</span>
                  </div>
                  <div className="rl-threat-list">
                    <div className="rl-threat-item rl-threat-critical">
                      <div className="rl-threat-severity">
                        <span className="rl-severity-dot rl-dot-critical"></span>
                        <span className="rl-severity-label">CRITICAL</span>
                      </div>
                      <div className="rl-threat-content">
                        <h4 className="rl-threat-name">WannaCry</h4>
                        <p className="rl-threat-impact">2017 • 300K+ devices globally</p>
                        <p className="rl-threat-desc">Exploited EternalBlue, crippled healthcare worldwide</p>
                      </div>
                    </div>
                    <div className="rl-threat-item rl-threat-high">
                      <div className="rl-threat-severity">
                        <span className="rl-severity-dot rl-dot-high"></span>
                        <span className="rl-severity-label">HIGH</span>
                      </div>
                      <div className="rl-threat-content">
                        <h4 className="rl-threat-name">REvil / Sodinokibi</h4>
                        <p className="rl-threat-impact">2019-2021 • $200M+ in ransom</p>
                        <p className="rl-threat-desc">Supply chain attacks via Kaseya VSA</p>
                      </div>
                    </div>
                    <div className="rl-threat-item rl-threat-critical">
                      <div className="rl-threat-severity">
                        <span className="rl-severity-dot rl-dot-critical"></span>
                        <span className="rl-severity-label">CRITICAL</span>
                      </div>
                      <div className="rl-threat-content">
                        <h4 className="rl-threat-name">Colonial Pipeline</h4>
                        <p className="rl-threat-impact">2021 • $4.4M ransom paid</p>
                        <p className="rl-threat-desc">DarkSide shut down US fuel pipeline</p>
                      </div>
                    </div>
                  </div>
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        <section className="rl-section" id="features" tabIndex={-1}>
          <div className="rl-section-inner">
            <Reveal>
              <h2 className="rl-section-title">What Powers The Portal</h2>
            </Reveal>
            <div className="rl-feature-grid">
              {featureCards.map((card, index) => (
                <Reveal key={card.title} delay={index * 80}>
                  <FeatureCard icon={card.icon} title={card.title} desc={card.desc} />
                </Reveal>
              ))}
            </div>
            <Reveal delay={320}>
              <div className="rl-architecture">
                <h3>Architecture Glimpse</h3>
                <div className="rl-architecture-steps">
                  {archSteps.map((step, index) => (
                    <ArchStep key={step.title} index={index + 1} title={step.title} desc={step.desc} />
                  ))}
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        <section className="rl-section" id="process" tabIndex={-1}>
          <div className="rl-section-inner">
            <Reveal>
              <h2 className="rl-section-title">How Teams Move From Alert To Containment</h2>
            </Reveal>
            <div className="rl-process-flow">
              {processFlow.map((step, index) => (
                <Reveal key={step.title} delay={index * 90}>
                  <ProcessItem index={index + 1} title={step.title} desc={step.desc} />
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        <section className="rl-section" id="faq" tabIndex={-1}>
          <div className="rl-section-inner">
            <Reveal>
              <h2 className="rl-section-title">Frequently Asked Questions</h2>
            </Reveal>
            <div className="rl-faq-grid">
              {faqList.map((faq, index) => (
                <Reveal key={faq.question} delay={index * 60}>
                  <FAQItem index={index} question={faq.question} answer={faq.answer} />
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        <section className="rl-section rl-cta" id="cta" tabIndex={-1}>
          <div className="rl-section-inner">
            <Reveal>
              <h3>Ready To Fortify Your Ransomware Playbook?</h3>
            </Reveal>
            <Reveal delay={80}>
              <p className="rl-cta-desc">
                Launch the portal, invite your response team, and turn every suspicious signal into a confident decision in minutes.
              </p>
            </Reveal>
            <Reveal delay={140}>
              <a className="rl-btn rl-btn-cta" href="/login">
                <span>Get Started</span>
                <ArrowIcon className="rl-btn-icon" />
              </a>
            </Reveal>
            <Reveal delay={200}>
              <p className="rl-cta-note">Select “Get Start” to go straight to the secure login experience.</p>
            </Reveal>
          </div>
        </section>
      </main>

      <footer className="rl-footer" role="contentinfo">
        <div className="rl-footer-content">
          <div className="rl-footer-brand">
            <ShieldIcon className="rl-footer-icon" />
            <span>Ransomware Portal</span>
          </div>
          <small>© {new Date().getFullYear()} Ransomware Intelligence Collective. All rights reserved.</small>
        </div>
      </footer>
      <style>{`
        :root {
          color-scheme: dark;
          --primary-gradient: linear-gradient(135deg, #0ea5e9 0%, #ec4899 100%);
          --glow-primary: rgba(14, 165, 233, 0.5);
          --glow-secondary: rgba(236, 72, 153, 0.5);
        }

        @keyframes float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          33% { transform: translateY(-20px) rotate(5deg); }
          66% { transform: translateY(-10px) rotate(-5deg); }
        }

        @keyframes particle-float {
          0%, 100% { transform: translate(0, 0); opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
        }

        @keyframes glow-pulse {
          0%, 100% { opacity: 0.5; }
          50% { opacity: 0.8; }
        }

        @keyframes chip-slide-in {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .rl-wrapper {
          height: 100vh;
          overflow-y: auto;
          scroll-snap-type: y mandatory;
          background: 
            radial-gradient(circle at 20% 20%, rgba(14, 165, 233, 0.08), transparent 50%),
            radial-gradient(circle at 80% 80%, rgba(236, 72, 153, 0.08), transparent 50%),
            linear-gradient(180deg, #020617 0%, #0f172a 50%, #020617 100%);
          color: rgba(248, 250, 252, 0.95);
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          position: relative;
        }

        .rl-wrapper:focus {
          outline: none;
        }

        .rl-particles {
          position: fixed;
          inset: 0;
          pointer-events: none;
          overflow: hidden;
        }

        .rl-particle {
          position: absolute;
          width: 2px;
          height: 2px;
          background: radial-gradient(circle, rgba(94, 234, 212, 0.8), transparent);
          border-radius: 50%;
          animation: particle-float linear infinite;
        }

        .rl-nav {
          position: sticky;
          top: 0;
          z-index: 40;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 1rem;
          padding: 1rem clamp(1.5rem, 4vw, 4rem);
          background: rgba(15, 23, 42, 0.75);
          backdrop-filter: blur(24px) saturate(180%);
          border-bottom: 1px solid rgba(148, 163, 255, 0.1);
          box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
        }

        .rl-nav-left {
          display: flex;
          align-items: center;
          gap: 1rem;
        }

        .rl-nav-logo {
          display: inline-flex;
          align-items: center;
          gap: 0.65rem;
          font-weight: 700;
          font-size: 1.1rem;
          letter-spacing: -0.01em;
          background: var(--primary-gradient);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .rl-nav-logo-icon {
          width: 32px;
          height: 32px;
          color: #0ea5e9;
          filter: drop-shadow(0 0 8px var(--glow-primary));
        }

        .rl-nav-links {
          display: none;
          align-items: center;
          gap: 1.5rem;
          font-size: 0.95rem;
        }

        .rl-nav-links a {
          position: relative;
          font-weight: 500;
          color: rgba(226, 232, 240, 0.9);
        }

        .rl-nav-links a::before {
          content: '';
          position: absolute;
          inset: auto 0 -0.4rem;
          height: 2px;
          background: var(--primary-gradient);
          transform: scaleX(0);
          transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .rl-nav-links a:hover::before {
          transform: scaleX(1);
        }

        .rl-nav-login {
          display: inline-flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.65rem 1.5rem;
          border-radius: 999px;
          background: rgba(14, 165, 233, 0.1);
          border: 1px solid rgba(14, 165, 233, 0.3);
          color: #f8fafc;
          font-weight: 600;
          text-decoration: none;
          transition: all 0.3s ease;
        }

        .rl-nav-login:hover {
          background: rgba(14, 165, 233, 0.2);
          border-color: rgba(14, 165, 233, 0.5);
          transform: translateY(-2px);
          box-shadow: 0 8px 20px rgba(14, 165, 233, 0.25);
        }

        .rl-nav-arrow {
          width: 18px;
          height: 18px;
          transition: transform 0.3s ease;
        }

        .rl-nav-login:hover .rl-nav-arrow {
          transform: translateX(4px);
        }

        .rl-main {
          position: relative;
          scroll-snap-align: start;
        }

        .rl-section {
          position: relative;
          min-height: 100vh;
          scroll-snap-align: start;
          display: flex;
          align-items: center;
          padding: 4rem clamp(1.5rem, 5vw, 5rem);
        }

        .rl-section-inner {
          width: min(1120px, 100%);
          margin: 0 auto;
        }

        .rl-section-title {
          font-size: clamp(2.1rem, 3vw, 3rem);
          letter-spacing: -0.02em;
          margin-bottom: 2.5rem;
        }

        .rl-hero {
          min-height: 100vh;
          padding-top: 6rem;
          padding-bottom: 6rem;
        }

        .rl-hero-grid {
          display: grid;
          grid-template-columns: 1fr;
          gap: 3rem;
          align-items: center;
          width: min(1100px, 100%);
          margin: 0 auto;
        }

        .rl-hero-badge {
          display: inline-flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.5rem 1rem;
          border-radius: 999px;
          background: rgba(14, 165, 233, 0.15);
          border: 1px solid rgba(14, 165, 233, 0.3);
          font-size: 0.85rem;
          font-weight: 600;
          margin-bottom: 2rem;
          animation: glow-pulse 3s ease-in-out infinite;
        }

        .rl-badge-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #10b981;
          animation: glow-pulse 2s ease-in-out infinite;
        }

        .rl-gradient-text {
          background: var(--primary-gradient);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          filter: drop-shadow(0 0 20px var(--glow-primary));
        }

        .rl-hero-stats {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 1.75rem;
          margin-top: 2rem;
          padding: 1.75rem 2rem;
          border-radius: 22px;
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid rgba(148, 163, 255, 0.12);
          backdrop-filter: blur(10px);
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
        }

        .rl-stat {
          text-align: center;
          padding: 0.5rem;
        }

        .rl-stat-number {
          font-size: 2.25rem;
          font-weight: 700;
          background: var(--primary-gradient);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          margin-bottom: 0.5rem;
          line-height: 1;
        }

        .rl-stat-label {
          font-size: 0.85rem;
          color: rgba(148, 163, 184, 0.9);
          line-height: 1.3;
        }

        .rl-hero-copy h1 {
          font-size: clamp(3rem, 6vw, 4.5rem);
          letter-spacing: -0.03em;
          margin-bottom: 1.5rem;
          line-height: 1.05;
        }

        .rl-hero-desc {
          max-width: 34rem;
          color: rgba(226, 239, 255, 0.78);
          margin-bottom: 2.5rem;
        }

        .rl-hero-actions {
          display: flex;
          flex-wrap: wrap;
          gap: 1rem;
          margin-bottom: 1.5rem;
        }

        .rl-ornament {
          position: absolute;
          width: clamp(280px, 32vw, 360px);
          height: clamp(280px, 32vw, 360px);
          border-radius: 50%;
          filter: blur(80px);
          opacity: 0.75;
          pointer-events: none;
        }

        .rl-ornament-left {
          top: 10%;
          left: 4%;
          background: radial-gradient(circle at center, rgba(14, 165, 233, 0.35), transparent 70%);
        }

        .rl-ornament-right {
          bottom: 12%;
          right: 6%;
          background: radial-gradient(circle at center, rgba(236, 72, 153, 0.3), transparent 70%);
        }

        .rl-btn {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.85rem 1.8rem;
          border-radius: 999px;
          font-weight: 600;
          font-size: 0.95rem;
          border: 1px solid transparent;
          cursor: pointer;
          transition: transform 0.2s ease, box-shadow 0.3s ease, border-color 0.3s ease;
        }

        .rl-btn:focus-visible {
          outline: 2px solid #38bdf8;
          outline-offset: 2px;
        }

        .rl-btn-primary {
          background: var(--primary-gradient);
          color: #fff;
          box-shadow: 0 10px 35px rgba(14, 165, 233, 0.25);
        }

        .rl-btn-primary:hover {
          transform: translateY(-2px);
          box-shadow: 0 12px 40px rgba(14, 165, 233, 0.35);
        }

        .rl-btn-animated {
          position: relative;
          overflow: hidden;
        }

        .rl-btn-animated::before {
          content: '';
          position: absolute;
          top: 50%;
          left: 50%;
          width: 0;
          height: 0;
          border-radius: 50%;
          background: rgba(255, 255, 255, 0.3);
          transform: translate(-50%, -50%);
          transition: width 0.6s ease, height 0.6s ease;
        }

        .rl-btn-animated:hover::before {
          width: 300px;
          height: 300px;
        }

        .rl-btn-secondary {
          background: rgba(14, 165, 233, 0.08);
          color: rgba(226, 239, 255, 0.85);
          border-color: rgba(14, 165, 233, 0.25);
        }

        .rl-btn-secondary:hover {
          border-color: rgba(14, 165, 233, 0.45);
        }

        .rl-btn-icon {
          width: 20px;
          height: 20px;
          transition: transform 0.3s ease;
        }

        .rl-btn:hover .rl-btn-icon {
          transform: translateX(4px);
        }

        .rl-btn-cta {
          display: inline-flex;
          align-items: center;
          gap: 0.75rem;
          padding: 1rem 2.5rem;
          border-radius: 999px;
          background: var(--primary-gradient);
          color: #fff;
          font-weight: 700;
          font-size: 1.05rem;
          border: none;
          text-decoration: none;
          box-shadow: 0 10px 40px rgba(14, 165, 233, 0.4);
          transition: all 0.3s ease;
        }

        .rl-btn-cta:hover {
          transform: translateY(-3px);
          box-shadow: 0 15px 50px rgba(14, 165, 233, 0.5);
        }

        .rl-hero-visual {
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
          align-items: center;
        }

        .rl-hero-panel {
          width: 100%;
          max-width: 520px;
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 1.25rem;
          padding: 2.5rem;
          border-radius: 28px;
          background: rgba(10, 15, 30, 0.8);
          border: 1px solid rgba(148, 163, 255, 0.12);
          backdrop-filter: blur(16px);
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .rl-chip {
          display: flex;
          gap: 0.85rem;
          padding: 1.1rem;
          border-radius: 20px;
          background: rgba(15, 23, 42, 0.8);
          border: 1px solid rgba(148, 163, 255, 0.12);
          transition: all 0.3s ease;
        }

        .rl-chip-animated {
          animation: chip-slide-in 0.6s cubic-bezier(0.4, 0, 0.2, 1) backwards;
        }

        .rl-chip:hover {
          transform: translateY(-4px);
          background: rgba(15, 23, 42, 0.95);
          border-color: rgba(14, 165, 233, 0.4);
          box-shadow: 0 8px 30px rgba(14, 165, 233, 0.2);
        }

        .rl-chip-icon svg {
          width: 28px;
          height: 28px;
          color: rgba(94, 234, 212, 0.8);
          flex-shrink: 0;
        }

        .rl-chip-title {
          font-weight: 600;
          font-size: 0.95rem;
        }

        .rl-chip-note {
          display: block;
          font-size: 0.8rem;
          color: rgba(199, 210, 254, 0.7);
        }

        .rl-two-column {
          display: grid;
          grid-template-columns: 1fr;
          gap: 2rem;
        }

        .rl-column-text {
          display: flex;
          flex-direction: column;
          justify-content: center;
        }

        .rl-column-text h3 {
          font-size: 1.3rem;
          margin-bottom: 1rem;
          color: rgba(248, 250, 252, 0.95);
        }

        .rl-column-text ul {
          list-style: none;
          padding-left: 0;
          color: rgba(226, 239, 255, 0.8);
        }

        .rl-column-text li {
          position: relative;
          padding-left: 1.75rem;
          margin-bottom: 1rem;
          line-height: 1.6;
        }

        .rl-column-text li::before {
          content: '→';
          position: absolute;
          left: 0;
          color: rgba(14, 165, 233, 0.8);
          font-weight: 700;
          font-size: 1.1rem;
        }

        .rl-column-text li + li {
          margin-top: 0;
        }

        .rl-threat-showcase {
          height: 100%;
          display: flex;
          flex-direction: column;
          padding: 1.75rem;
          border-radius: 24px;
          background: linear-gradient(135deg, rgba(10, 15, 30, 0.95), rgba(15, 23, 42, 0.9));
          border: 1px solid rgba(148, 163, 255, 0.15);
          backdrop-filter: blur(20px);
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
          position: relative;
          overflow: hidden;
        }

        .rl-threat-showcase::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 3px;
          background: var(--primary-gradient);
        }

        .rl-threat-header {
          margin-bottom: 1.25rem;
          padding-bottom: 1rem;
          border-bottom: 1px solid rgba(148, 163, 255, 0.1);
          flex-shrink: 0;
        }

        .rl-threat-title {
          font-size: 1.15rem;
          font-weight: 700;
          margin: 0 0 0.4rem 0;
          background: var(--primary-gradient);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .rl-threat-subtitle {
          font-size: 0.8rem;
          color: rgba(148, 163, 184, 0.8);
        }

        .rl-threat-list {
          display: flex;
          flex-direction: column;
          gap: 0.85rem;
          flex: 1;
        }

        .rl-threat-item {
          position: relative;
          display: flex;
          gap: 0.85rem;
          padding: 1rem 1rem 1rem 0.85rem;
          border-radius: 14px;
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid rgba(148, 163, 255, 0.12);
          transition: all 0.3s ease;
          cursor: pointer;
        }

        .rl-threat-item::before {
          content: '';
          position: absolute;
          left: 0;
          top: 0;
          bottom: 0;
          width: 3px;
          border-radius: 3px 0 0 3px;
          opacity: 0.8;
        }

        .rl-threat-critical::before {
          background: linear-gradient(180deg, #ef4444, #dc2626);
        }

        .rl-threat-high::before {
          background: linear-gradient(180deg, #f59e0b, #d97706);
        }

        .rl-threat-item:hover {
          transform: translateX(4px);
          background: rgba(15, 23, 42, 0.8);
          border-color: rgba(14, 165, 233, 0.3);
          box-shadow: 0 4px 20px rgba(14, 165, 233, 0.2);
        }

        .rl-threat-severity {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 0.4rem;
          padding-top: 0.25rem;
          flex-shrink: 0;
        }

        .rl-severity-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          animation: glow-pulse 2s ease-in-out infinite;
        }

        .rl-dot-critical {
          background: #ef4444;
          box-shadow: 0 0 12px rgba(239, 68, 68, 0.8);
        }

        .rl-dot-high {
          background: #f59e0b;
          box-shadow: 0 0 12px rgba(245, 158, 11, 0.8);
        }

        .rl-severity-label {
          font-size: 0.65rem;
          font-weight: 700;
          letter-spacing: 0.05em;
          color: rgba(148, 163, 184, 0.9);
          writing-mode: vertical-rl;
          text-orientation: mixed;
        }

        .rl-threat-content {
          flex: 1;
          min-width: 0;
        }

        .rl-threat-name {
          font-size: 1rem;
          font-weight: 700;
          margin: 0 0 0.35rem 0;
          color: rgba(248, 250, 252, 0.95);
        }

        .rl-threat-impact {
          font-size: 0.75rem;
          font-weight: 600;
          color: rgba(94, 234, 212, 0.9);
          margin: 0 0 0.35rem 0;
        }

        .rl-threat-desc {
          font-size: 0.8rem;
          line-height: 1.4;
          color: rgba(148, 163, 184, 0.8);
          margin: 0;
        }

        .rl-feature-grid {
          display: grid;
          grid-template-columns: 1fr;
          gap: 1.5rem;
          margin-bottom: 3rem;
        }

        .rl-glow-card {
          position: relative;
          border-radius: 24px;
          overflow: hidden;
        }

        .rl-glow-card-effect {
          position: absolute;
          inset: 0;
          background: radial-gradient(
            600px circle at var(--mouse-x, 50%) var(--mouse-y, 50%),
            rgba(14, 165, 233, 0.15),
            transparent 40%
          );
          opacity: 0;
          transition: opacity 0.3s ease;
        }

        .rl-glow-card:hover .rl-glow-card-effect {
          opacity: 1;
        }

        .rl-glow-card-content {
          position: relative;
          z-index: 1;
        }

        .rl-card {
          padding: 1.75rem;
          border-radius: 24px;
          background: rgba(11, 18, 34, 0.8);
          border: 1px solid rgba(148, 163, 255, 0.12);
          box-shadow: 0 10px 40px rgba(15, 23, 42, 0.25);
          transition: transform 0.3s ease, border-color 0.3s ease, background 0.3s ease;
        }

        .rl-card:hover {
          transform: translateY(-6px);
          border-color: rgba(94, 234, 212, 0.35);
          background: rgba(11, 18, 34, 0.92);
        }

        .rl-card-icon svg {
          width: 32px;
          height: 32px;
          color: rgba(94, 234, 212, 0.85);
        }

        .rl-card h3 {
          font-size: 1.3rem;
          margin-top: 1.2rem;
          margin-bottom: 0.75rem;
        }

        .rl-card p {
          color: rgba(213, 224, 255, 0.75);
        }

        .rl-architecture {
          padding: 2rem;
          border-radius: 24px;
          border: 1px solid rgba(148, 163, 255, 0.12);
          background: rgba(9, 12, 24, 0.75);
        }

        .rl-architecture h3 {
          font-size: 1.4rem;
          margin-bottom: 1.5rem;
        }

        .rl-architecture-steps {
          display: grid;
          gap: 1.2rem;
        }

        .rl-arch-step {
          display: flex;
          gap: 1.1rem;
          align-items: flex-start;
        }

        .rl-arch-index {
          font-weight: 700;
          font-size: 1.4rem;
          color: rgba(94, 234, 212, 0.8);
        }

        .rl-process-flow {
          display: grid;
          grid-template-columns: 1fr;
          gap: 1.5rem;
        }

        .rl-process-item {
          padding: 1.8rem;
          border-radius: 22px;
          border: 1px solid rgba(148, 163, 255, 0.12);
          background: rgba(10, 16, 32, 0.75);
        }

        .rl-process-badge {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 40px;
          height: 40px;
          border-radius: 12px;
          background: linear-gradient(135deg, rgba(14, 165, 233, 0.35), rgba(236, 72, 153, 0.35));
          font-weight: 700;
          margin-bottom: 1rem;
        }

        .rl-process-item h3 {
          font-size: 1.2rem;
          margin-bottom: 0.6rem;
        }

        .rl-faq-grid {
          display: grid;
          grid-template-columns: 1fr;
          gap: 1rem;
        }

        .rl-faq-item {
          padding: 1.4rem 1.6rem;
          border-radius: 18px;
          border: 1px solid rgba(148, 163, 255, 0.12);
          background: rgba(12, 19, 35, 0.72);
        }

        .rl-faq-item summary {
          list-style: none;
          display: flex;
          align-items: center;
          justify-content: space-between;
          cursor: pointer;
          font-weight: 600;
        }

        .rl-faq-item summary::-webkit-details-marker {
          display: none;
        }

        .rl-faq-item summary:focus-visible {
          outline: 2px solid #38bdf8;
          border-radius: 12px;
        }

        .rl-faq-body {
          margin-top: 0.9rem;
          color: rgba(213, 224, 255, 0.78);
        }

        .rl-faq-arrow {
          width: 20px;
          height: 20px;
          transition: transform 0.3s ease;
        }

        .rl-faq-item[open] .rl-faq-arrow {
          transform: rotate(90deg);
        }

        .rl-cta {
          min-height: 70vh;
          position: relative;
          overflow: hidden;
        }

        .rl-cta-gradient {
          position: absolute;
          inset: 0;
          background: radial-gradient(
            ellipse at center,
            rgba(14, 165, 233, 0.15) 0%,
            transparent 70%
          );
          animation: glow-pulse 4s ease-in-out infinite;
        }

        .rl-cta h3 {
          font-size: clamp(2rem, 3vw, 3rem);
          letter-spacing: -0.02em;
          margin-bottom: 1.3rem;
        }

        .rl-cta-desc {
          max-width: 480px;
          color: rgba(226, 239, 255, 0.78);
          margin-bottom: 2rem;
        }

        .rl-footer {
          border-top: 1px solid rgba(148, 163, 255, 0.1);
          padding: 2rem clamp(1.5rem, 4vw, 4rem);
          background: rgba(15, 23, 42, 0.5);
        }

        .rl-footer-content {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 1rem;
          text-align: center;
        }

        .rl-footer-brand {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-weight: 600;
          color: rgba(226, 232, 240, 0.9);
        }

        .rl-footer-icon {
          width: 24px;
          height: 24px;
          color: #0ea5e9;
        }

        .rl-footer small {
          font-size: 0.85rem;
          color: rgba(148, 163, 255, 0.65);
        }

        .rl-ornament {
          animation: float 8s ease-in-out infinite;
        }

        .rl-progress {
          position: fixed;
          top: 50%;
          right: clamp(1rem, 3vw, 2rem);
          transform: translateY(-50%);
          z-index: 50;
          width: 6px;
          height: 60vh;
        }

        .rl-progress-track {
          width: 100%;
          height: 100%;
          border-radius: 999px;
          background: rgba(71, 85, 105, 0.35);
          overflow: hidden;
        }

        .rl-progress-bar {
          width: 100%;
          height: 100%;
          border-radius: 999px;
          background: linear-gradient(180deg, rgba(94, 234, 212, 0.9), rgba(236, 72, 153, 0.9));
          transform-origin: top;
          transform: scaleY(0);
          transition: transform 0.2s ease-out;
        }

        .rl-reveal {
          opacity: 0;
          transform: translateY(24px);
          transition: opacity 0.7s ease, transform 0.7s ease;
        }

        .rl-reveal--visible {
          opacity: 1;
          transform: translateY(0);
        }

        @media (min-width: 640px) {
          .rl-nav-links {
            display: flex;
          }
        }

        @media (min-width: 768px) {
          .rl-hero-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
            align-items: center;
            gap: 3rem;
          }

          .rl-two-column {
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 3rem;
          }

          .rl-feature-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .rl-process-flow {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .rl-faq-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .rl-footer-content {
            flex-direction: row;
            justify-content: space-between;
          }
        }

        @media (min-width: 1024px) {
          .rl-feature-grid {
            grid-template-columns: repeat(4, minmax(0, 1fr));
          }

          .rl-process-flow {
            grid-template-columns: repeat(4, minmax(0, 1fr));
          }

          .rl-faq-grid {
            grid-template-columns: repeat(3, minmax(0, 1fr));
          }
        }

        @media (max-width: 480px) {
          .rl-nav {
            padding: 0.85rem 1.25rem;
          }

          .rl-btn {
            width: 100%;
            justify-content: center;
          }

          .rl-progress {
            right: 0.75rem;
            height: 45vh;
          }

          .rl-hero-stats {
            grid-template-columns: 1fr;
            gap: 1rem;
          }

          .rl-stat-number {
            font-size: 1.75rem;
          }

          .rl-stat-label {
            font-size: 0.75rem;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          *,
          *::before,
          *::after {
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.01ms !important;
            scroll-behavior: auto !important;
          }
        }
      `}</style>
    </div>
  );
}


