import { useState } from "react";

export function LandingScreen({
  onGoToLogin,
}: {
  onGoToLogin: () => void;
}) {
  const [activeStep, setActiveStep] = useState<number>(1);
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  const toggleFaq = (index: number) => {
    setOpenFaq(openFaq === index ? null : index);
  };

  return (
    <div className="standalone-container">
      {/* Landing Navbar */}
      <nav className="landing-nav">
        <div className="nav-brand" onClick={onGoToLogin}>
          <span className="nav-brand-logo">U</span>
          <span>UniConfig</span>
        </div>
        <div className="nav-links">
          <a href="#features" className="btn" style={{ background: "transparent" }}>
            Features
          </a>
          <a href="#demo" className="btn" style={{ background: "transparent" }}>
            Interactive Demo
          </a>
          <a href="#pricing" className="btn" style={{ background: "transparent" }}>
            Pricing
          </a>
          <a href="#faq" className="btn" style={{ background: "transparent" }}>
            FAQ
          </a>
          <button onClick={onGoToLogin} className="btn-red">
            Log in to Dashboard
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="hero-card">
        <span className="badge badge-red" style={{ marginBottom: 16 }}>
          SIH 2026 Problem Statement SIH26155 • NTRO
        </span>
        <h1>Unified Configuration Platform for Every Network</h1>
        <p>
          AI-driven multi-vendor security compliance auditor. UniConfig normalizes Cisco,
          Juniper, Fortinet, AWS, and legacy network CLI configurations into a single baseline,
          evaluating them against CIS Benchmarks, NIST SP 800-53, DISA STIGs, and ISO 27001.
        </p>

        <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
          <button onClick={onGoToLogin} className="btn-red" style={{ padding: "12px 28px", fontSize: "1rem" }}>
            Launch System
          </button>
          <a href="#demo" className="btn-dark" style={{ padding: "12px 24px", fontSize: "1rem" }}>
            Explore Interactive Demo
          </a>
        </div>

        <div className="hero-stats-grid">
          <div className="hero-stat-item">
            <span className="hero-stat-number">70%</span>
            <span className="hero-stat-label">Less manual audit effort</span>
          </div>
          <div className="hero-stat-item">
            <span className="hero-stat-number">80%+</span>
            <span className="hero-stat-label">Faster compliance prep</span>
          </div>
          <div className="hero-stat-item">
            <span className="hero-stat-number">50%</span>
            <span className="hero-stat-label">Less remediation effort</span>
          </div>
          <div className="hero-stat-item">
            <span className="hero-stat-number">100+</span>
            <span className="hero-stat-label">CIS Benchmarks covered</span>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <section id="features" className="card">
        <span className="badge badge-dark" style={{ marginBottom: 12 }}>
          Core Capabilities
        </span>
        <h2>Why Enterprise & Government Defense Teams Choose UniConfig</h2>
        <p>Turning multi-vendor CLI complexity into structured compliance clarity.</p>

        <div className="grid-3" style={{ marginTop: 24 }}>
          <div className="card" style={{ background: "var(--light-bg)" }}>
            <span className="badge badge-red" style={{ marginBottom: 8 }}>
              01 • Heterogeneous Parsing
            </span>
            <h3 style={{ marginTop: 4 }}>Multi-Vendor Normalization</h3>
            <p>
              Parses Cisco IOS/NX-OS, Juniper JunOS, Fortinet FortiGATE, and AWS Security Groups
              into one canonical JSON security model.
            </p>
          </div>

          <div className="card" style={{ background: "var(--light-bg)" }}>
            <span className="badge badge-dark" style={{ marginBottom: 8 }}>
              02 • Air-Gapped AI
            </span>
            <h3 style={{ marginTop: 4 }}>Air-Gapped RAG Intelligence</h3>
            <p>
              Runs 100% on-premise with local vector databases and local LLMs. Zero sensitive configuration data leaves your perimeter.
            </p>
          </div>

          <div className="card" style={{ background: "var(--light-bg)" }}>
            <span className="badge badge-red" style={{ marginBottom: 8 }}>
              03 • Multi-Standard
            </span>
            <h3 style={{ marginTop: 4 }}>Unified Compliance Engine</h3>
            <p>
              Single-pass audit against CIS Benchmarks, NIST SP 800-53 Rev. 5, DISA STIGs, and ISO/IEC 27001:2022.
            </p>
          </div>

          <div className="card" style={{ background: "var(--light-bg)" }}>
            <span className="badge badge-dark" style={{ marginBottom: 8 }}>
              04 • Adaptive Learning
            </span>
            <h3 style={{ marginTop: 4 }}>Self-Improving Vendor Queue</h3>
            <p>
              Unrecognized CLI syntax lines are queued for human-guided training, permanently expanding parser coverage for custom OS versions.
            </p>
          </div>

          <div className="card" style={{ background: "var(--light-bg)" }}>
            <span className="badge badge-red" style={{ marginBottom: 8 }}>
              05 • Remediation
            </span>
            <h3 style={{ marginTop: 4 }}>Automated CLI Fix Scripts</h3>
            <p>
              Generates exact copyable CLI remediation commands for failed controls and exportable PDF audit evidence reports.
            </p>
          </div>

          <div className="card" style={{ background: "var(--light-bg)" }}>
            <span className="badge badge-dark" style={{ marginBottom: 8 }}>
              06 • Zero Hallucinations
            </span>
            <h3 style={{ marginTop: 4 }}>LLM Grounding & Validation</h3>
            <p>
              All AI suggestions undergo strict schema validation and vendor documentation verification to ensure 100% audit accuracy.
            </p>
          </div>
        </div>
      </section>

      {/* Interactive User Tutorial Section */}
      <section id="demo" className="card">
        <span className="badge badge-red" style={{ marginBottom: 12 }}>
          Interactive User Tutorial
        </span>
        <h2>How UniConfig Works: Step-by-Step Simulator</h2>
        <p>Click through the workflow steps below to explore how UniConfig evaluates network configurations.</p>

        <div className="tutorial-steps">
          <button
            className={`tutorial-step-btn ${activeStep === 1 ? "active" : ""}`}
            onClick={() => setActiveStep(1)}
          >
            1. Upload & Vendor Detection
          </button>
          <button
            className={`tutorial-step-btn ${activeStep === 2 ? "active" : ""}`}
            onClick={() => setActiveStep(2)}
          >
            2. RAG & Schema Normalization
          </button>
          <button
            className={`tutorial-step-btn ${activeStep === 3 ? "active" : ""}`}
            onClick={() => setActiveStep(3)}
          >
            3. Multi-Standard Compliance Audit
          </button>
          <button
            className={`tutorial-step-btn ${activeStep === 4 ? "active" : ""}`}
            onClick={() => setActiveStep(4)}
          >
            4. CLI Remediation & Reports
          </button>
        </div>

        <div className="tutorial-box">
          {activeStep === 1 && (
            <div>
              <span className="badge badge-red" style={{ marginBottom: 8 }}>Step 1</span>
              <h3 style={{ color: "#FFF", marginTop: 4 }}>Upload Device Configuration & Hardware Info</h3>
              <p style={{ color: "var(--text-light-muted)" }}>
                The user provides a running-config file (e.g. Cisco `show running-config`) and a hardware version file (e.g. `show version`). UniConfig automatically identifies the vendor and OS hierarchy.
              </p>
              <pre>
                {`[Input Files Received]
├── running-config.txt  (Cisco IOS 15.2 WS-C2960)
└── version.txt         (Serial: FOC1827A1, Model: Catalyst 2960)
[Auto-Detected Vendor]: Cisco IOS`}
              </pre>
            </div>
          )}

          {activeStep === 2 && (
            <div>
              <span className="badge badge-red" style={{ marginBottom: 8 }}>Step 2</span>
              <h3 style={{ color: "#FFF", marginTop: 4 }}>RAG Parsing & Grounded LLM Validation</h3>
              <p style={{ color: "var(--text-light-muted)" }}>
                The air-gapped parser extracts security facts (SSH versions, TACACS+ auth, AAA, logging) and validates them against local vector DB embeddings.
              </p>
              <pre>
                {`[RAG Schema Normalization]
{
  "device_id": "cisco-2960-core-01",
  "ssh_version_2_enabled": false,
  "aaa_new_model_enabled": true,
  "logging_server_configured": true
}`}
              </pre>
            </div>
          )}

          {activeStep === 3 && (
            <div>
              <span className="badge badge-red" style={{ marginBottom: 8 }}>Step 3</span>
              <h3 style={{ color: "#FFF", marginTop: 4 }}>Multi-Standard Compliance Verdicts</h3>
              <p style={{ color: "var(--text-light-muted)" }}>
                The evaluation engine compares schema facts against rule packs. Controls are color-coded with High (Red), Medium (Yellow), and Low (Green) severity.
              </p>
              <pre>
                {`[Compliance Audit Verdicts]
• CIS-4.1  (Use SSH version 2 only)        ➜ FAIL  [High Severity]
• NIST-8.3 (Configure AAA authentication)   ➜ PASS  [Low Severity]
• ISO-27001 A.9.4.2 (Secure Log Transfer)   ➜ PASS  [Evidence Present]`}
              </pre>
            </div>
          )}

          {activeStep === 4 && (
            <div>
              <span className="badge badge-red" style={{ marginBottom: 8 }}>Step 4</span>
              <h3 style={{ color: "#FFF", marginTop: 4 }}>Automated CLI Remediation & PDF Export</h3>
              <p style={{ color: "var(--text-light-muted)" }}>
                UniConfig generates ready-to-run vendor CLI commands to fix failed controls and compiles an executive PDF audit report.
              </p>
              <pre>
                {`[Remediation Script Generated]
configure terminal
  ip ssh version 2
  crypto key generate rsa modulus 2048
end
write memory`}
              </pre>
            </div>
          )}
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="card">
        <span className="badge badge-dark" style={{ marginBottom: 12 }}>
          Subscription & Licensing
        </span>
        <h2>Flexible Operational Pricing Models</h2>
        <p>Tailored for cloud teams, enterprise network operations, and air-gapped government defense.</p>

        <div className="grid-3" style={{ marginTop: 24 }}>
          {/* Tier 1 */}
          <div className="pricing-card">
            <div>
              <span className="badge badge-dark" style={{ marginBottom: 12 }}>Starter SaaS</span>
              <h3 style={{ fontSize: "1.8rem", margin: "12px 0 4px 0" }}>$49 <span style={{ fontSize: "0.9rem", color: "var(--text-muted)", fontWeight: 500 }}>/ mo</span></h3>
              <p style={{ fontSize: "0.9rem" }}>Ideal for small IT teams evaluating standard cloud & branch routers.</p>
              <ul style={{ paddingLeft: 18, fontSize: "0.9rem", color: "var(--text-muted)", lineHeight: "1.8" }}>
                <li>Up to 25 devices evaluated</li>
                <li>CIS & NIST Rule Packs</li>
                <li>PDF Compliance Exports</li>
                <li>Community Support</li>
              </ul>
            </div>
            <button onClick={onGoToLogin} className="btn-dark" style={{ marginTop: 20 }}>
              Get Started
            </button>
          </div>

          {/* Tier 2 (Featured) */}
          <div className="pricing-card featured">
            <span className="pricing-badge">Recommended for Enterprise</span>
            <div>
              <span className="badge badge-red" style={{ marginBottom: 12 }}>Air-Gapped Enterprise</span>
              <h3 style={{ fontSize: "1.8rem", margin: "12px 0 4px 0" }}>On-Prem License</h3>
              <p style={{ fontSize: "0.9rem" }}>One-time perpetual licensing with AMC support for Defense, Banking & Gov.</p>
              <ul style={{ paddingLeft: 18, fontSize: "0.9rem", color: "var(--text-muted)", lineHeight: "1.8" }}>
                <li>Unlimited devices & vendors</li>
                <li>100% Air-Gapped Local LLM RAG</li>
                <li>CIS, NIST, DISA STIG & ISO 27001</li>
                <li>Custom Vendor Parser Training</li>
                <li>24/7 Priority AMC Support</li>
              </ul>
            </div>
            <button onClick={onGoToLogin} className="btn-red" style={{ marginTop: 20 }}>
              Request Enterprise License
            </button>
          </div>

          {/* Tier 3 */}
          <div className="pricing-card">
            <div>
              <span className="badge badge-dark" style={{ marginBottom: 12 }}>Custom Packs</span>
              <h3 style={{ fontSize: "1.8rem", margin: "12px 0 4px 0" }}>Custom Add-Ons</h3>
              <p style={{ fontSize: "0.9rem" }}>Custom YAML compliance modules for specialized industry frameworks.</p>
              <ul style={{ paddingLeft: 18, fontSize: "0.9rem", color: "var(--text-muted)", lineHeight: "1.8" }}>
                <li>Custom YAML Rule Modules</li>
                <li>Specialized Hardware Parsers</li>
                <li>Onboarding & Training Assistance</li>
                <li>Dedicated Solutions Architect</li>
              </ul>
            </div>
            <button onClick={onGoToLogin} className="btn-dark" style={{ marginTop: 20 }}>
              Contact Sales
            </button>
          </div>
        </div>
      </section>

      {/* FAQ Section (Based on SIH26155-PPTX.pdf) */}
      <section id="faq" className="card">
        <span className="badge badge-red" style={{ marginBottom: 12 }}>
          Frequently Asked Questions
        </span>
        <h2>Everything You Need to Know About UniConfig</h2>
        <p>Insights derived from our SIH 2026 architecture and security benchmarks.</p>

        <div style={{ marginTop: 20 }}>
          <div className="faq-item">
            <div className="faq-question" onClick={() => toggleFaq(0)}>
              <span>What cybersecurity compliance standards does UniConfig evaluate?</span>
              <span>{openFaq === 0 ? "−" : "+"}</span>
            </div>
            {openFaq === 0 && (
              <div className="faq-answer">
                UniConfig provides comprehensive single-pass audits across CIS Benchmarks (Center for Internet Security), NIST SP 800-53 Rev. 5, DISA STIGs (Defense Information Systems Agency), and ISO/IEC 27001:2022 Annex A control objectives.
              </div>
            )}
          </div>

          <div className="faq-item">
            <div className="faq-question" onClick={() => toggleFaq(1)}>
              <span>How does UniConfig handle unknown or custom vendor CLI syntax?</span>
              <span>{openFaq === 1 ? "−" : "+"}</span>
            </div>
            {openFaq === 1 && (
              <div className="faq-answer">
                UniConfig features an adaptive, self-improving vendor queue. When an unrecognized vendor config is uploaded, unparsed lines are sent to the Vendor Training queue where admins map them to security categories once. Confirmed mappings automatically become permanent, reusable rules for future uploads.
              </div>
            )}
          </div>

          <div className="faq-item">
            <div className="faq-question" onClick={() => toggleFaq(2)}>
              <span>Can UniConfig run in 100% air-gapped defense or banking networks?</span>
              <span>{openFaq === 2 ? "−" : "+"}</span>
            </div>
            {openFaq === 2 && (
              <div className="faq-answer">
                Yes! UniConfig offers a fully local, on-premise air-gapped architecture. It uses local LLM anomaly engines (such as Ollama) and local vector embeddings, ensuring no sensitive configuration or network data ever leaves your organization's perimeter.
              </div>
            )}
          </div>

          <div className="faq-item">
            <div className="faq-question" onClick={() => toggleFaq(3)}>
              <span>How does UniConfig prevent AI hallucinations during audits?</span>
              <span>{openFaq === 3 ? "−" : "+"}</span>
            </div>
            {openFaq === 3 && (
              <div className="faq-answer">
                UniConfig grounds all AI outputs using a RAG (Retrieval-Augmented Generation) vector architecture combined with a deterministic schema validator. Suggested mappings are verified against official vendor documentation before final presentation.
              </div>
            )}
          </div>

          <div className="faq-item">
            <div className="faq-question" onClick={() => toggleFaq(4)}>
              <span>What impact does UniConfig have on network outage risks?</span>
              <span>{openFaq === 4 ? "−" : "+"}</span>
            </div>
            {openFaq === 4 && (
              <div className="faq-answer">
                Studies show that 46% of major network outages stem from configuration and change-management errors. UniConfig reduces manual audit effort by 70%, speeds up compliance preparation by over 80%, and halves remediation effort through instant CLI fix scripts.
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="card card-dark" style={{ textAlign: "center", marginTop: 32 }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <span className="nav-brand-logo">U</span>
          <span style={{ fontWeight: 800, fontSize: "1.2rem", color: "#FFF" }}>UniConfig</span>
        </div>
        <p style={{ color: "var(--text-light-muted)", fontSize: "0.88rem" }}>
          Smart India Hackathon 2026 • Problem Statement SIH26155 • National Technical Research Organisation (NTRO)
          <br />
          Developed by <strong>Team TechTadkaa</strong> (Team ID: 9E5544)
        </p>
      </footer>
    </div>
  );
}
