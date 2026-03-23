/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Document, Page, pdfjs } from 'react-pdf';
import 'react-pdf/dist/Page/AnnotationLayer.css';
import 'react-pdf/dist/Page/TextLayer.css';

// Set up the worker for pdfjs
pdfjs.GlobalWorkerOptions.workerSrc = `//unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.mjs`;

import { 
  Github, FileText, Activity, ExternalLink, BookOpen, 
  Terminal, Server, CheckCircle2, PlayCircle, Settings, BarChart,
  Folder, FileCode, Archive, ChevronRight, Zap, Search, ShieldAlert,
  Moon, Sun
} from 'lucide-react';

// --- Data Structures ---

const projectStructure = [
  { name: 'core-open5gs.yaml', type: 'file', desc: 'Open5GS 5G core configuration' },
  { name: 'docker-compose.yaml', type: 'file', desc: 'Orchestration of O-RAN, RIC, and core components' },
  { name: 'Dockerfile', type: 'file', desc: 'Container image for ORANClaw experiments' },
  { name: 'gnb-oai.yaml', type: 'file', desc: 'OAI gNB configuration (CU/DU)' },
  { name: 'requirements.sh', type: 'file', desc: 'System-level dependency installation' },
  { name: 'configs', type: 'folder', desc: 'Configuration files for O-RAN components', children: [
    { name: 'flexric.conf', type: 'file', desc: 'Near-RT RIC configuration' },
    { name: 'xapp.conf', type: 'file', desc: 'xApp configuration redirecting RIC IP (.129) to localhost' }
  ]},
  { name: 'asn1', type: 'folder', desc: 'ASN.1 specifications, code generation, and fuzzing logic', children: [
    { name: 'asn1files', type: 'folder', desc: 'E2AP and E2SM ASN.1 specifications' },
    { name: 'asn1c', type: 'folder', desc: 'ASN.1 compiler and runtime support' },
    { name: 'src', type: 'folder', desc: 'Generated and E2AP/E2SM encoders and decoders', children: [
      { name: 'reader.cpp', type: 'file', desc: 'Customized encoder (PER-> JER)' },
      { name: 'reader_json.cpp', type: 'file', desc: 'Customized decoder (JER-> PER)' }
    ]},
    { name: 'client_server.py', type: 'file', desc: 'ASN.1-aware fuzzing engine (OAI version)' },
    { name: 'captures_bridge', type: 'folder', desc: 'Capture files generated during fuzzing sessions' },
    { name: 'container_logs', type: 'folder', desc: 'OAI docker logs files generated during fuzzing sessions' },
    { name: 'fuzzing_logs', type: 'folder', desc: 'Fuzzer logs generated during fuzzing sessions' },
    { name: 'state_machines', type: 'folder', desc: 'Learned E2 protocol state machines' },
    { name: 'state_machines_diff', type: 'folder', desc: 'Behavioral diffs between benign and fuzzed sessions' },
    { name: 'gen-code.sh', type: 'file', desc: 'Generate C/C++ code from ASN.1 files script' }
  ]},
  { name: 'captures', type: 'folder', desc: 'PCAP traces from baseline and attack experiments', children: [
    { name: 'baseline.pcapng', type: 'file', desc: 'Benign baseline capture file' }
  ]},
  { name: 'libs', type: 'folder', desc: 'Precompiled FlexRIC service models', children: [
    { name: 'flexric', type: 'folder', desc: 'KPM, RC, MAC, RLC, PDCP, and TC service models' }
  ]},
  { name: 'scripts', type: 'folder', desc: 'Experiment automation and UE management', children: [
    { name: 'add_subscribers.sh', type: 'file', desc: 'Registers UEs in Open5GS (MongoDB)' },
    { name: 'run_ue_iperf.sh', type: 'file', desc: 'Traffic generation for evaluation' }
  ]},
  { name: 'docs', type: 'folder', desc: 'Design diagrams and system overview figures' },
  { name: 'vakt-ble-defender.zip', type: 'file', desc: 'Pre-compiled binaries to create the state machines' },
  { name: 'asn1c.zip', type: 'file', desc: 'Pre-compiled binaries of asn1c' }
];

const logStructure = [
  { name: 'Logs_ORANCLAW', type: 'folder', desc: 'Pre-collected logs and raw data', children: [
    { name: 'Logs_NS3', type: 'folder', desc: 'ns-3 ablation experiments', children: [
      { name: 'Ablation_2', type: 'folder', desc: 'Extended ablation study', children: [
        { name: 'plot.py', type: 'file', desc: 'ns3 Ablation, Figure 7 of the paper' }
      ]},
      { name: 'RQ1', type: 'folder', desc: 'RQ1/RQ2 shared analysis utilities', children: [
        { name: 'average.py', type: 'file', desc: 'ns3 cummulative bugs, Figure 5 of the paper' }
      ]}
    ]},
    { name: 'LogsOAI', type: 'folder', desc: 'OAI ablation experiments', children: [
      { name: 'Ablation', type: 'folder', desc: 'OAI ablation analysis', children: [
        { name: 'plot.py', type: 'file', desc: 'Ablation result visualization (Figure 6)' },
        { name: 'sm_completness.py', type: 'file', desc: 'State Machine completness (Figure 8)' }
      ]},
      { name: 'RQ1', type: 'folder', desc: 'OAI statistical analysis', children: [
        { name: 'average_new_SM.py', type: 'file', desc: 'OAI cummulative bugs, Figure 4' }
      ]},
      { name: 'RQ3', type: 'folder', desc: 'Efficiency of the bridge', children: [
        { name: 'latency_wisec.py', type: 'file', desc: 'Efficiency boxplot (Figure 9)' }
      ]}
    ]}
  ]}
];

// --- Reusable Components ---

const FileTreeItem: React.FC<{ item: any, depth?: number }> = ({ item, depth = 0 }) => {
  const [isOpen, setIsOpen] = useState(true);
  const isFolder = item.type === 'folder';
  
  return (
    <div className="font-mono text-sm">
      <div 
        className={`flex items-center gap-2 py-1.5 px-2 hover:bg-slate-800/50 rounded-md ${isFolder ? 'cursor-pointer' : ''}`}
        style={{ paddingLeft: `${depth * 1.5 + 0.5}rem` }}
        onClick={() => isFolder && setIsOpen(!isOpen)}
      >
        {isFolder ? (
          <Folder className={`h-4 w-4 shrink-0 ${isOpen ? 'text-indigo-400' : 'text-slate-500'}`} />
        ) : item.name.endsWith('.zip') ? (
          <Archive className="h-4 w-4 text-amber-400 shrink-0" />
        ) : item.name.endsWith('.sh') || item.name.endsWith('.py') ? (
          <FileCode className="h-4 w-4 text-cyan-400 shrink-0" />
        ) : (
          <FileText className="h-4 w-4 text-slate-400 shrink-0" />
        )}
        <span className={`font-medium ${isFolder ? 'text-slate-200' : 'text-slate-300'}`}>{item.name}</span>
        {item.desc && <span className="text-slate-500 text-xs hidden sm:inline-block truncate ml-2">- {item.desc}</span>}
      </div>
      {isFolder && isOpen && item.children && (
        <div>
          {item.children.map((child: any, idx: number) => (
            <FileTreeItem key={idx} item={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
};

const CodeBlock = ({ code, language = 'bash', title, isLog = false, collapsible = false }: any) => {
  const [isOpen, setIsOpen] = useState(!collapsible);

  const renderCode = () => {
    if (isLog || language !== 'bash') return code;
    
    const commands = [
      'cd', 'wget', 'mkdir', 'unzip', 'rm', 'chmod', 'source', 'docker', 
      'python3', 'echo', 'sudo', 'apt', 'apt-key', 'tee', 'git', 'cp', 
      'tar', 'ls', 'mv', 'npm', 'npx', 'yarn', 'pnpm', 'compose', 'up', 
      'exec', 'install', 'update', 'clone', 'checkout', 'add', 'commit', 
      'push', 'iperf3'
    ];
    const cmdRegex = new RegExp(`\\b(${commands.join('|')})\\b`, 'g');
    
    return code.split('\n').map((line: string, lineIdx: number, arr: string[]) => {
      const commentIndex = line.indexOf('#');
      let codePart = line;
      let commentPart = '';
      
      if (commentIndex !== -1) {
        codePart = line.substring(0, commentIndex);
        commentPart = line.substring(commentIndex);
      }
      
      const highlightedCode = codePart.split(cmdRegex).map((part, i) => {
        if (commands.includes(part)) {
          return <span key={i} className="text-cyan-400 font-semibold">{part}</span>;
        }
        return part;
      });
      
      return (
        <React.Fragment key={lineIdx}>
          {highlightedCode}
          {commentPart && <span className="text-slate-500 italic">{commentPart}</span>}
          {lineIdx < arr.length - 1 && '\n'}
        </React.Fragment>
      );
    });
  };

  const content = (
    <div className="rounded-xl overflow-hidden border border-slate-800 bg-[#0d1117] my-4 shadow-sm">
      {title && (
        <div className="bg-slate-900/80 px-4 py-2.5 border-b border-slate-800 flex items-center gap-2">
          <Terminal className="h-4 w-4 text-slate-400" />
          <span className="text-xs font-medium text-slate-300 font-mono tracking-wide">{title}</span>
        </div>
      )}
      <div className="p-4 overflow-x-auto">
        <pre className={`text-sm font-mono leading-relaxed ${isLog ? 'text-slate-400' : 'text-slate-200'}`}>
          <code>{renderCode()}</code>
        </pre>
      </div>
    </div>
  );

  if (collapsible) {
    return (
      <div className="my-4">
        <button 
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-2 text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 transition-colors"
        >
          <ChevronRight className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
          {isOpen ? 'Hide' : 'View'} {isLog ? 'Log Output' : 'Code'}
        </button>
        {isOpen && content}
      </div>
    );
  }
  return content;
};

// --- Main Application ---

export default function App() {
  const [isDark, setIsDark] = useState(false);
  const [activeTab, setActiveTab] = useState('setup');
  const [numPages, setNumPages] = useState<number>();
  const [pageNumber, setPageNumber] = useState<number>(1);

  React.useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  function onDocumentLoadSuccess({ numPages }: { numPages: number }): void {
    setNumPages(numPages);
  }

  const tabs = [
    { id: 'setup', label: '1. Setup & Installation', icon: <CheckCircle2 className="h-4 w-4" /> },
    { id: 'oai', label: '2. OAI Evaluation', icon: <Server className="h-4 w-4" /> },
    { id: 'ns3', label: '3. ns-3 Evaluation', icon: <Activity className="h-4 w-4" /> },
    { id: 'rq1', label: '4. RQ1: Bug Finding', icon: <Search className="h-4 w-4" /> },
    { id: 'rq2', label: '5. RQ2: Ablation Study', icon: <BarChart className="h-4 w-4" /> },
    { id: 'rq3', label: '6. RQ3: Efficiency', icon: <Zap className="h-4 w-4" /> },
    { id: 'customization', label: '7. Customization & Logs', icon: <Settings className="h-4 w-4" /> },
  ];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 font-sans text-slate-900 dark:text-slate-100 selection:bg-indigo-100 dark:selection:bg-indigo-900/50 selection:text-indigo-900 dark:selection:text-indigo-200">
      {/* Navigation */}
      <nav className="sticky top-0 z-50 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-950/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3 font-bold tracking-tight text-slate-900 dark:text-white text-xl">
            <img src={`${import.meta.env.BASE_URL}Logo.png`} alt="ORANClaw Logo" className="h-16 w-16 object-contain" />
            <span>ORANClaw</span>
          </div>
          <div className="hidden items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-400 sm:flex">
            <a href="#overview" className="hover:text-indigo-600 dark:text-indigo-400 dark:hover:text-indigo-400 transition-colors">Overview</a>
            <a href="#reproducibility" className="hover:text-indigo-600 dark:text-indigo-400 dark:hover:text-indigo-400 transition-colors">Reproducibility Guide</a>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsDark(!isDark)}
              className="p-2 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
              aria-label="Toggle theme"
            >
              {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <a 
              href="https://github.com/asset-group" 
              target="_blank" 
              rel="noreferrer"
              className="flex items-center gap-2 rounded-full bg-slate-900 dark:bg-white px-4 py-2 text-sm font-medium text-white dark:text-slate-900 transition-transform hover:scale-105"
            >
              <Github className="h-4 w-4" />
              <span>GitHub</span>
            </a>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <header className="relative overflow-hidden bg-white dark:bg-slate-950 px-6 py-24 sm:py-32">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]"></div>
        <div className="relative mx-auto max-w-5xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="flex justify-center mb-8">
              <img src={`${import.meta.env.BASE_URL}Logo.png`} alt="ORANClaw Logo" className="h-56 w-auto object-contain drop-shadow-xl dark:drop-shadow-[0_20px_20px_rgba(255,255,255,0.05)]" />
            </div>
            <h3 className="font-serif text-3xl font-semibold tracking-tight text-slate-900 dark:text-white sm:text-4xl">
              ORANClaw<br className="hidden sm:block" />
              <span className="text-indigo-600 dark:text-indigo-400">Giving E2-nodes a Bad Day via Structure-Aware MiTM Fuzzing</span>
            </h3>
            <p className="mx-auto mt-8 max-w-2xl text-lg leading-relaxed text-slate-600 dark:text-slate-400">
              A structure-aware, man-in-the-middle fuzzing framework that takes full control over the E2 interface between xApps and the RIC to systematically mutate packets and disrupt base station behavior.
            </p>
          </motion.div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-16 sm:py-24">
        {/* Overview Section */}
        <section id="overview" className="scroll-mt-24 mb-24">
          <div className="mb-12">
            <h2 className="text-sm font-bold uppercase tracking-widest text-indigo-600 dark:text-indigo-400">01 / Overview</h2>
            <h3 className="mt-2 text-3xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">Framework Design</h3>
            <p className="mt-4 text-slate-600 dark:text-slate-400 max-w-3xl">
              ORANClaw is a novel structure-aware Man-in-the-Middle (MiTM) fuzzing framework specifically designed to evaluate the security and robustness of E2 Nodes within the Open Radio Access Network (O-RAN) architecture.
            </p>
          </div>
          
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 sm:p-10 shadow-sm">
            <div className="prose prose-slate max-w-none">
              <p className="text-slate-600 dark:text-slate-400 leading-relaxed mb-8">
                By intercepting and mutating E2 Application Protocol (E2AP) messages between the Near-Real-Time RAN Intelligent Controller (Near-RT RIC) and the E2 Nodes (such as O-CU and O-DU), ORANClaw leverages structural awareness of the protocol to generate highly effective test cases. This allows it to uncover deep-seated vulnerabilities, state-machine flaws, and memory corruption bugs that traditional fuzzers might miss.
              </p>
              
              <div className="rounded-xl overflow-hidden border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 flex flex-col items-center justify-center p-4">
                <Document
                  file={`${import.meta.env.BASE_URL}DesignBetter-1.pdf`}
                  onLoadSuccess={onDocumentLoadSuccess}
                  className="w-full flex justify-center"
                  loading={
                    <div className="flex items-center justify-center h-[600px] text-slate-500 dark:text-slate-400">
                      <Activity className="w-6 h-6 animate-spin mr-2" />
                      Loading PDF...
                    </div>
                  }
                  error={
                    <div className="flex flex-col items-center justify-center h-[600px] text-slate-500 dark:text-slate-400">
                      <ShieldAlert className="w-8 h-8 text-red-500 mb-2" />
                      <p>Failed to load PDF.</p>
                      <a href={`${import.meta.env.BASE_URL}DesignBetter-1.pdf`} target="_blank" rel="noopener noreferrer" className="text-indigo-600 dark:text-indigo-400 hover:underline mt-2">
                        Download the PDF instead
                      </a>
                    </div>
                  }
                >
                  <Page 
                    pageNumber={pageNumber} 
                    renderTextLayer={false}
                    renderAnnotationLayer={false}
                    className="max-w-full"
                    width={Math.min(window.innerWidth - 80, 800)}
                  />
                </Document>
                {numPages && (
                  <div className="flex items-center gap-4 mt-4 text-sm text-slate-600 dark:text-slate-400">
                    <button 
                      disabled={pageNumber <= 1}
                      onClick={() => setPageNumber(prev => Math.max(prev - 1, 1))}
                      className="px-3 py-1 rounded bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <span>Page {pageNumber} of {numPages}</span>
                    <button 
                      disabled={pageNumber >= numPages}
                      onClick={() => setPageNumber(prev => Math.min(prev + 1, numPages))}
                      className="px-3 py-1 rounded bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-4 text-center italic">
                Figure: The high-level design and architecture of the ORANClaw fuzzing framework.
              </p>
            </div>
          </div>
        </section>

        {/* Reproducibility Guide */}
        <section id="reproducibility" className="scroll-mt-24">
          <div className="mb-12">
            <h2 className="text-sm font-bold uppercase tracking-widest text-indigo-600 dark:text-indigo-400">02 / Artifacts</h2>
            <h3 className="mt-2 text-3xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">Reproducibility Guide</h3>
            <p className="mt-4 text-slate-600 dark:text-slate-400 max-w-3xl">Comprehensive instructions to deploy the Dockerized environment, run ORANClaw fuzzing sessions, and reproduce the paper's results across OpenAirInterface and ns-3 simulators.</p>
          </div>

          <div className="flex flex-col lg:flex-row gap-8">
            {/* Sidebar Tabs */}
            <div className="lg:w-1/4 flex flex-col gap-2 shrink-0">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-3 rounded-xl px-4 py-3.5 text-sm font-medium transition-all ${
                    activeTab === tab.id
                      ? 'bg-indigo-600 dark:bg-indigo-500 text-white shadow-md shadow-indigo-200 dark:shadow-none'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-white dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 hover:shadow-sm'
                  }`}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="lg:w-3/4 min-h-[600px] rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 sm:p-10 shadow-sm">
              
              {/* TAB 1: SETUP & INSTALLATION */}
              {activeTab === 'setup' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                  
                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">1. Hardware & Software Requirements</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-6">The artifact leverages Docker containers to minimize environmental dependencies and facilitate testing on standard x86_64 hardware.</p>
                    
                    <div className="grid sm:grid-cols-2 gap-6">
                      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-5">
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-3 flex items-center gap-2">
                          <Server className="h-4 w-4 text-indigo-600 dark:text-indigo-400" /> Hardware
                        </h5>
                        <ul className="list-disc pl-5 space-y-2 text-sm text-slate-600 dark:text-slate-400">
                          <li><strong>CPU:</strong> Minimum 4 cores (8+ cores recommended for concurrent fuzzing).</li>
                          <li><strong>RAM:</strong> Minimum 16GB (32GB recommended for stable OAI gNB + UE simulation).</li>
                          <li><strong>Storage:</strong> At least 20GB free. Up to 500GB if uncompressing logs for RQs.</li>
                        </ul>
                      </div>
                      
                      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-5">
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-3 flex items-center gap-2">
                          <Terminal className="h-4 w-4 text-indigo-600 dark:text-indigo-400" /> Software
                        </h5>
                        <ul className="list-disc pl-5 space-y-2 text-sm text-slate-600 dark:text-slate-400">
                          <li><strong>OS:</strong> Ubuntu 24.04 (Main runtime environment)</li>
                          <li><strong>Docker:</strong> Latest version for container orchestration.</li>
                          <li><strong>Python ≥ 3.12:</strong> Required for the MitM Fuzzing Engine.</li>
                          <li><strong>TShark ≥ 4.2.2:</strong> For capturing E2AP/SCTP traffic.</li>
                          <li><strong>asn1c compiler ≥ 7.8:</strong> For encoding/decoding ASN.1.</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">1.2 Project Structure</h4>
                    <div className="rounded-xl border border-slate-800 bg-[#0d1117] p-4 overflow-x-auto">
                      {projectStructure.map((item, idx) => (
                        <FileTreeItem key={idx} item={item} />
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">1.3 Software Installation (build from source)</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-6">The installation of the ORANClaw testbed is facilitated through Docker. Follow these steps to prepare the environment.</p>
                    
                    <div className="space-y-8">
                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">1</span>
                          Clone ORANClaw repository
                        </h5>
                        <CodeBlock code={`cd $HOME
wget https://zenodo.org/records/18580510/files/ORANClaw-E2-MitM-Fuzzing.zip?download=1 -O ORANClaw-E2-MitM-Fuzzing-AFFC.zip
mkdir ORANClaw-E2-MitM-Fuzzing-AFFC
unzip ORANClaw-E2-MitM-Fuzzing-AFFC.zip -d ORANClaw-E2-MitM-Fuzzing-AFFC
rm -rf ORANClaw-E2-MitM-Fuzzing-AFFC.zip
cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">2</span>
                          Install System Requirements
                        </h5>
                        <CodeBlock code={`chmod +x requirements.sh
./requirements.sh
source $HOME/.venvs/oran-env/bin/activate # activate virtual env`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">3</span>
                          Install wdissector & asn1c
                        </h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">Pre-compiled binaries are provided for convenience.</p>
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC
wget -O vakt-ble-defender.zip https://zenodo.org/records/18368683/files/vakt-ble-defender.zip?download=1
unzip vakt-ble-defender
rm -rf vakt-ble-defender.zip

cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/asn1
wget https://zenodo.org/records/18368683/files/asn1c.zip?download=1 -O asn1c.zip
unzip asn1c.zip
rm -rf asn1c.zip
chmod +x ./reader
chmod +x ./reader_json`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">4</span>
                          Add custom ASN.1 versions (gen-code.sh)
                        </h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">ORANClaw is designed to be specification-agnostic. You can download different versions of E2AP into the <code>/asn1files</code> directory.</p>
                        <CodeBlock title="gen-code.sh script" code={`#gen-code.sh file:
./asn1c/bin/asn1c \\
asn1files/E2SM-KPM-v05.00.asn \\ ##Add your file name here
asn1files/asn_flexric/e2sm_rc_v1_03_modified.asn \\ ##Add your file name here
asn1files/asn_flexric/e42ap_v2_03.asn -genTest \\ ##Add your file name here
-per -json -w32 -server -depends -events -genPrtToStr \\
-list -reader -trace -c++ -print -prtfmt details \\
-srcdir src -make Makefile -w32 -table-unions -stream -pdu all`} />
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* TAB 2: OAI EVALUATION */}
              {activeTab === 'oai' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                  
                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">2.1 Evaluating ORANClaw with OpenAirInterface</h4>
                    
                    <div className="space-y-8">
                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">1</span>
                          Start Core Network
                        </h5>
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC
docker compose --profile core up # Terminal 1 - Core Network`} />
                        <CodeBlock isLog collapsible title="Core Network example output" code={`udr-1 | 04/12 07:58:12.304: [sbi] INFO: [6250a1de-f8a2-41ee-bdd9-0f6b7e1be1b5] NF registered [\\
Heartbeat:10s] (../lib/sbi/nf-sm.c:221)
udm-1 | 04/12 07:58:12.304: [sbi] INFO: (NRF-notify) NF registered [6250a1de-f8a2-41ee-bdd9-0f6b7e1be\\
1b5:1] (../lib/sbi/nnrf-handler.c:924)
udm-1 | 04/12 07:58:12.304: [sbi] INFO: [UDR] (NRF-notify) NF Profile updated [6250a1de-f8a2-41ee-bdd\\
9-0f6b7e1be1b5:1] (../lib/sbi/nnrf-handler.c:938)`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">2</span>
                          Add UE Subscribers
                        </h5>
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/scripts/
./add_subcribers.sh`} />
                        <CodeBlock isLog title="UE Registration output example" code={`{
  acknowledged: true,
  insertedId: ObjectId('6618ec5e2d06d1bb877b2da9')
}
Done!`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">3</span>
                          Start the O-RAN gNB, UE simulation, and Near-Real-Time RIC
                        </h5>
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/
docker compose --profile gnb-rfsim up # Terminal 2 - gNB + UE Simulation + Near Realtime RIC`} />
                        <CodeBlock isLog title="UE Logs example" code={`oai-ue-rfsimu-2-1 | [NR_PHY] ============================================
oai-ue-rfsimu-2-1 | [NR_PHY] Harq round stats for Downlink: 2735/1/0
oai-ue-rfsimu-2-1 | [NR_PHY] ============================================`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">4</span>
                          Run commands in the UE (iperf)
                        </h5>
                        <CodeBlock title="UE to Core Network" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/
docker compose exec -it oai-ue-rfsimu-1 iperf3 -c 10.45.0.1 -t0 # Terminal 3 - UE to Core Transfer`} />
                        <CodeBlock isLog title="UE Uplink/Downlink output example" code={`[ ID] Interval       Transfer     Bitrate       Retr
[  5] 0.00-1.65 sec  22.2 MBytes  113 Mbits/sec 0       sender`} />
                      </div>
                    </div>
                  </div>

                  <hr className="border-slate-200 dark:border-slate-800" />

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">2.2 Running ORANClaw (OAI)</h4>
                    
                    <div className="space-y-8">
                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">1</span>
                          Start the Fuzzer
                        </h5>
                        <CodeBlock title="client_server.py script" code={`IP_MITM = "192.168.71.129"
IP_XAPP = "192.168.71.185"
IP_RIC  = "192.168.71.184"`} />
                        <CodeBlock title="Launch the fuzzer" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/asn1
python3 client_server.py`} />
                        <CodeBlock isLog title="ORANClaw SCTP MITM Proxy Output" code={`==================================================
SCTP MITM Proxy - Starting
==================================================
[+] Started tshark capture
[Genetic Algorithm] Enabled
[+] Connected to RIC at 192.168.71.184:36422
[*] Listening for xApp on 192.168.71.129:36422...
[*] Fuzzing enabled: True (Probability: 20.0%)
[*] Waiting for new xApp connection...
Capturing on '5g-oran'`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">2</span>
                          Start xApp
                        </h5>
                        <CodeBlock title="docker-compose.yaml content example" code={`xapp-kpm-monitor:
  profiles: [xapp]
  image: researchanon2025/flexric-components:v1.0
  restart: unless-stopped
  tty: true
  privileged: true
  command: /bin/bash -c
           "./build/examples/xApp/c/monitor/xapp_kpm_moni
- -c ./configs/flexric.conf
+ -c ./configs/xapp.conf # overrides RIC IP to localhost
           && sleep infinity"`} />
                        <CodeBlock title="Start xApp KPI monitoring" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/
docker compose --profile xapp up # Terminal 4 - xAPP`} />
                        <CodeBlock isLog title="xApp Output" code={`xapp-kpm-monitor-1 | ran_ue_id = 1
xapp-kpm-monitor-1 | DRB.RlcSduDelayDl = 6014.82 [µs]
xapp-kpm-monitor-1 | DRB.UEThpDl = 250493.20 [kbps]
xapp-kpm-monitor-1 | DRB.UEThpUl = 4843.06 [kbps]
xapp-kpm-monitor-1 | RRU.PrbTotDl = 354196 [PRBs]
xapp-kpm-monitor-1 | RRU.PrbTotUl = 30572 [PRBs]`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">3</span>
                          Automated testing
                        </h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">This script launches an infinite fuzzing session, periodically restarting the xApp every 15 seconds to create multiple independent sessions.</p>
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/
python3 docker_monitoring.py`} />
                        <CodeBlock isLog collapsible title="docker_monitoring.py output" code={`2026-01-25 15:51:37,686 - INFO -
=== 5G O-RAN Synchronized Monitor Started ===
2026-01-25 15:51:37,686 - INFO - Container logs: ././asn1/container_logs/
2026-01-25 15:51:37,686 - INFO - Fuzzing logs: ././asn1/fuzzing_logs/
2026-01-25 15:51:37,693 - INFO -
Starting synchronized monitor...
2026-01-25 15:51:37,693 - INFO - Auto-recovery: oai-du-rfsim, oai-cu-cp, oai-cu-up, nearRT-RIC
2026-01-25 15:51:37,695 - INFO - Starting services...
[+] up 15/15
Network 5g-oran-net Created
Container oranclaw-e2-mitm-fuzzing-mongo-1 Created
Container oranclaw-e2-mitm-fuzzing-webui-1 Created
Container oranclaw-e2-mitm-fuzzing-nrf-1 Created
...
2026-01-25 15:51:51,542 - INFO - Starting MiTM fuzzing session: 20260125_155151
2026-01-25 15:51:51,543 - INFO - MiTM session started`} />
                        <CodeBlock isLog collapsible title="Example fuzzing log output (mitm_session_YYYYMMDD_HHMMSS.log)" code={`==================================================
SCTP MITM Proxy - Starting
==================================================
[+] Started tshark capture
[Genetic Algorithm] Enabled
[+] Connected to RIC at 192.168.71.184:36422
[*] Listening for xApp on 192.168.71.129:36422...
[*] Fuzzing enabled: True (Probability: 20.0%)
[*] Waiting for new xApp connection...
Capturing on '5g-oran'
[+] Accepted xApp connection from ('192.168.71.185', 54189)
[TX] [xApp --> RIC]
[DEBUG]Length: 492 bytes
[*] ProcedureCode: 0xe
[DEBUG] Message Type: E42setup
--------------------------------------------------
[RX] [xApp <-- RIC]
[DEBUG]Length: 2389 bytes
[*] ProcedureCode: 0xe
[DEBUG] Response Type: E42setup
[DEBUG] Overhead: 0.32 ms
--------------------------------------------------
[*] Randomized weights for fuzzing strategies: [0.53, 0.38, 0.09]
[*] Selected fuzzing strategy: json
[DEBUG] Selected JSON fields to mutate: ['criticality']
[DEBUG] Generated new value for criticality: notify
[+] Mutated initiatingMessage.value.protocolIEs[0].value[0].criticality: reject -> notify
[+] Successfully fuzzed message (509 bytes)
[DEBUG] Overhead: 6.74 ms`} />
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* TAB 3: NS3 EVALUATION */}
              {activeTab === 'ns3' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                  
                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">2.3 Evaluating ORANClaw with ns-3 O-RAN Simulator</h4>
                    
                    <div className="space-y-8">
                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">1</span>
                          Install ns-3 O-RAN Simulator
                        </h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">Building from source is required to evaluate the ns-3 O-RAN simulator.</p>
                        <CodeBlock code={`cd $HOME
git clone https://github.com/Orange-OpenSource/ns-O-RAN-flexric.git
cd ns-O-RAN-flexric
git checkout 7936f62f`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">2</span>
                          Configure Fuzzing Engine for ns-3
                        </h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">Modify line 21 of <code>client_server_ns3.py</code> to use the host machine's IP address.</p>
                        <CodeBlock title="client_server_ns3.py configuration" code={`IP_MITM = "192.168.71.129" # change to your host IP
IP_XAPP = "127.0.0.1"
IP_RIC  = "127.0.0.1"`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">3</span>
                          Update ASN.1 Specifications for ns-3 Compatibility
                        </h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">The ns-O-RAN simulator relies on E2AP v1.01 and E2SM-KPM v3.00. Modify the ASN.1 input files referenced in the <code>gen-code.sh</code> script.</p>
                        <CodeBlock title="gen-code.sh update" code={`./asn1c/bin/asn1c asn1files/e2ap-v01.01.asn asn1files/e2sm_kpm_v03.00.asn -genTest \\
-genTest \\
-per -json -w32 -server -depends -events -genPrtToStr \\
-list -reader -trace -c++ -print -prtfmt details \\
-srcdir src -make Makefile -w32 -table-unions -stream -pdu all`} />
                        <CodeBlock title="Regenerate encoder and decoder" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing-AFFC/
./gen-code.sh`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">3.1</span>
                          Changing the baseline capture
                        </h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">Modify line 1736 of the script <code>client_server_ns3.py</code> to select another pcapng file for the SM_DIFF component.</p>
                        <CodeBlock title="wdmapper_gen_diff() function update example" code={`wdmapper_gen_diff = [
  "./bin/wdmapper",
  "--udp-dst-port=36421,38412,9999,38472,38412,36422",
  "-d", current_file,
- "-i", '../../../captures/Baseline_kpm_mon.pcapng',
+ "-i", '../../../captures/Baseline_kpm_rc_ns3.pcapng',
  "-c", "./configs/5gnr\\_gnb\\_config.json",
  "-o", (os.path.join(self.state\\_machines\\_diff\\_folder,f"wdmapper\\_diff\\_{self.timestamp}.\\
svg"))
]`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2 flex items-center gap-2">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 text-xs">4</span>
                          Run Automated Fuzzing
                        </h5>
                        <CodeBlock code={`cd $HOME/oran-orchestration/asn1
./ns3_fuzzing.sh`} />
                        <CodeBlock isLog collapsible title="Example of client_server_ns3.py script output" code={`==================================================
SCTP MITM Proxy - Starting
==================================================
[+] Created capture files folder: ns3/oran-orchestration/asn1/captures_bridge
[+] Created state machines folder: ns3/oran-orchestration/asn1/state_machines
[+] Created state machines diff folder: ns3/oran-orchestration/asn1/state_machines_diff
[+] Started tshark capture
[+] Connected to RIC at 127.0.0.1:36422
[*] Listening for xApp on 192.168.1.155:36422...
[*] Fuzzing enabled: True (Probability: 20.0%)
[*] Waiting for new xApp connection...
Capturing on 'Loopback: lo'
[+] Accepted xApp connection from ('192.168.1.155', 40907)
[TX] [xApp --> RIC]
[DEBUG][39mLength: 509 bytes
[*] ProcedureCode: 0xc
[DEBUG] Message Type: E42setup
[*] ProcedureCode: 0xc`} />
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* TAB 4: RQ1 BUG FINDING */}
              {activeTab === 'rq1' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                  
                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">3. Evaluation of effectiveness in finding bugs (RQ1)</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-4">Our objective is to replicate the effectiveness of the fuzzing sessions, as presented in Figures 4 and 5 in the paper. We collected the logs for each implementation (OAI and ns3) under the <code>Logs_ORANCLAW</code> directory.</p>
                    
                    <CodeBlock title="Download Pre-collected Logs (38.3 GB zip -> 492.4 GB uncompressed)" code={`cd $HOME
wget -O Logs_ORANCLAW.zip https://zenodo.org/records/18389642/files/Logs_ORANCLAW.zip?download=1
unzip -p Logs_ORANCLAW.zip | tar -xvf -`} />
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">3.1 Log Organization</h4>
                    <div className="rounded-xl border border-slate-800 bg-[#0d1117] p-4 overflow-x-auto">
                      {logStructure.map((item, idx) => (
                        <FileTreeItem key={idx} item={item} />
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">3.2 OpenAirInterface</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-4">To facilitate replication of our results, we provide an automation script that generates Figure 4 of the paper.</p>
                    <CodeBlock code={`source $HOME/.venvs/oran-env/bin/activate
cd $HOME/Logs_ORANCLAW/LogsOAI/RQ1
python3 average_new_SM.py`} />
                    <CodeBlock isLog title="average_new_SM.py output example" code={`Using BASE_PATH: /Logs_ORANCLAW/LogsOAI
Processing Mutation scenario...
Processing run 1/5: /Logs_ORANCLAW/LogsOAI/RQ1/OAIRand1/container_logs/
Time range: 2025-07-29 09:33:57 to 2025-07-30 09:33:28 (24.0h)
Found 31 unique crashes, 31 within 24.0h window
Processing run 2/5: /Logs_ORANCLAW/LogsOAI/RQ1/OAIRand2/container_logs/
Time range: 2025-07-29 09:34:01 to 2025-07-30 09:43:13 (24.2h)
Found 24 unique crashes, 24 within 24.0h window
Processing run 3/5: /Logs_ORANCLAW/LogsOAI/RQ1/OAIRand3/container_logs/
Time range: 2025-07-30 09:55:59 to 2025-07-31 09:55:57 (24.0h)
...`} />
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">3.3 ns-3</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-4">Similarly, we include a Python script that aggregates results across multiple ns-3 fuzzing runs and computes the average number of unique crashes over time, corresponding to Figure 5.</p>
                    <CodeBlock code={`source $HOME/.venvs/oran-env/bin/activate
cd $HOME/Logs_ORANCLAW/Logs_NS3/RQ1/
python3 average.py`} />
                    <CodeBlock isLog title="average.py output example" code={`Using BASE_PATH: Logs_ORANCLAW/Logs_NS3
Processing Mutation scenario...
Processing run 1/5: Logs_ORANCLAW/Logs_NS3/RQ1/Ns3Opt1/container_logs/
Time range: 2025-07-25 14:57:48 to 2025-07-26 15:00:33 (24.0h)
Found 31 unique crashes, 31 within 24.0h window
Processing run 2/5: Logs_ORANCLAW/Logs_NS3/RQ1/Ns3Opt2/container_logs/
Time range: 2025-07-25 14:58:08 to 2025-07-26 15:00:37 (24.0h)
Found 29 unique crashes, 29 within 24.0h window
...
Using 5/5 valid runs
Normalizing to 24.0 hours (shortest run duration)
Completed Mutation: Average final count = 31.8`} />
                  </div>
                </motion.div>
              )}

              {/* TAB 5: RQ2 COMPONENTS & ABLATION */}
              {activeTab === 'rq2' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                  
                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">4. Evaluation the effectiveness of ORANClaw components (RQ2)</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-4">This section describes how to reproduce the ablation study presented in RQ2, which evaluates the individual contribution of ORANClaw's fuzzing components.</p>
                    
                    <CodeBlock title="calculate_fuzzing_cost function in client_server.py (line 1867)" code={`def calculate_fuzzing_cost(self, target_fields=None, max_mutations=1,
                           alpha=0, beta=40, mu=0.1, t=20, timestamp=None):
    """
    Calculate the cost/reward function for fuzzing based on state machine exploration.
    """
    ...`} />
                    
                    <CodeBlock title="Genetic optimizer configuration in client_server.py (line 128)" code={`class GeneticFuzzerOptimizer:
    def __init__(self, population_size=6,
                 mutation_rate=0.3):
        ...`} />
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">4.1 OpenAirInterface Ablation</h4>
                    <CodeBlock code={`cd $HOME/Logs_ORANCLAW/LogsOAI/Ablation/
source $HOME/.venvs/oran-env/bin/activate
python3 plot.py`} />
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">5. ns-3 Ablation</h4>
                    <CodeBlock code={`cd $HOME/Logs_ORANCLAW/Logs_NS3/Ablation_2/
source $HOME/.venvs/oran-env/bin/activate
python3 plot.py`} />
                    <CodeBlock isLog title="Example output of ns-3 ablation aggregation script" code={`Using BASE_PATH: /media/p3rplex/data/Logs_ORANCLAW/Logs_NS3
Processing Optimization...
Optimization: 34 unique crashes saved to unique_crashes_opt.csv
Processing Mutation...
Mutation: 32 unique crashes saved to unique_crashes_random.csv
Processing Optimization + Dup...
Optimization + Dup: 34 unique crashes saved to unique_crashes_opt_mut_dup.csv
Processing Mutation + Dup...
Mutation + Dup: 33 unique crashes saved to unique_crashes_rand_mut_dup.csv
Processing Dup Only...`} />
                  </div>

                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">5.1 State-machine completeness analysis (OAI)</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-4">To reproduce the state-machine completeness study (Figure 8 of the paper), run the dedicated script that compares fuzzing runs generated from complete and incomplete state-machine traces.</p>
                    <CodeBlock code={`cd $HOME/Logs_ORANCLAW/LogsOAI/Ablation/
source $HOME/.venvs/oran-env/bin/activate
python3 sm_completness.py`} />
                    <CodeBlock isLog title="Example output of state-machine completeness analysis" code={`Using BASE_PATH: /media/p3rplex/data/Logs_ORANCLAW/LogsOAI
Processing Optimization...
Processing Mutation...
Processing Dup Only...
Processing Mutation + Dup...
Processing Optimization + Dup...
Processing Optimization ($\\beta$=0)...`} />
                  </div>
                </motion.div>
              )}

              {/* TAB 6: RQ3 EFFICIENCY */}
              {activeTab === 'rq3' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                  
                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">6. Evaluation of efficiency of ORANClaw (RQ3)</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-4">The goal of this experiment is to quantify the per-packet latency overhead introduced by ORANClaw when operating as an inline E2 bridge between the xApp and the RIC.</p>
                    
                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-6 mb-8">
                      <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-3">6.1 Latency Measurement Methodology</h5>
                      <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">For every E2AP packet forwarded through the bridge, ORANClaw logs the processing latency incurred between packet reception and packet transmission. This latency is reported directly in the runtime logs as a per-packet metric:</p>
                      <CodeBlock isLog code={`[DEBUG] Overhead: X ms`} />
                      <p className="text-sm text-slate-600 dark:text-slate-400 mt-4">Latency is recorded for both transmission directions: <strong>TX</strong> (RIC to gNB) and <strong>RX</strong> (gNB to RIC).</p>
                    </div>

                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-6 mb-8">
                      <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-3">6.2 Fuzzed vs Unprocessed</h5>
                      <div className="space-y-4">
                        <div>
                          <strong className="text-slate-900 dark:text-slate-100 text-sm">1) Unprocessed messages:</strong>
                          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">Packets are forwarded without decoding or mutation. Simple forwarding incurs sub-millisecond overhead:</p>
                          <CodeBlock isLog code={`[DEBUG] Overhead: 0.50 ms`} />
                        </div>
                        <div>
                          <strong className="text-slate-900 dark:text-slate-100 text-sm">2) Fuzzed messages:</strong>
                          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">Fuzzing is enabled and packets undergo full ASN.1 decoding, JSON conversion, mutation, and re-encoding. Packets undergoing full processing exhibit higher latency:</p>
                          <CodeBlock isLog code={`[DEBUG] Overhead: 22.67 ms`} />
                        </div>
                      </div>
                    </div>

                    <div className="space-y-6">
                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2">6.3 Log Collection</h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">All raw logs used in this evaluation are pre-collected and included in the artifact under:</p>
                        <CodeBlock isLog code={`Logs_ORANCLAW/LogsOAI/RQ3/`} />
                      </div>

                      <div>
                        <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-2">6.4 Latency Analysis and Plot Generation</h5>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">To generate the latency boxplot shown in Figure 9 of the paper, execute the following script:</p>
                        <CodeBlock code={`cd $HOME/Logs_ORANCLAW/LogsOAI/RQ3/
source $HOME/.venvs/oran-env/bin/activate
python3 latency_wisec.py`} />
                        <p className="text-sm text-slate-600 dark:text-slate-400 mt-3">The script separates latency samples corresponding to bypass and processing modes, and generates a combined boxplot comparing the two configurations.</p>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* TAB 7: CUSTOMIZATION & LOGS */}
              {activeTab === 'customization' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                  <div>
                    <h4 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-4">7. Customization & Zenodo Logs</h4>
                    <p className="text-slate-600 dark:text-slate-400 mb-6">
                      ORANClaw is designed to be highly flexible and customizable. The reproduction scripts and the tool itself can be adapted to different environments and use cases.
                    </p>

                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-6 mb-8">
                      <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-3">7.1 Tool Customization</h5>
                      <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
                        As specified in the artifacts, ORANClaw can be customized in several ways to target different components or protocols:
                      </p>
                      <ul className="list-disc pl-5 space-y-2 text-sm text-slate-600 dark:text-slate-400">
                        <li><strong>Changing the Capture Reference:</strong> You can provide different PCAP/capture files as reference seeds for the fuzzer to learn from different traffic patterns.</li>
                        <li><strong>Adding Different Service Models:</strong> The framework can be extended to support new O-RAN Service Models (SMs) by integrating their respective specifications.</li>
                        <li><strong>Different ASN.1 Files:</strong> By supplying different ASN.1 definitions, ORANClaw can automatically adapt its mutation and decoding strategies to new or updated E2AP/SM structures.</li>
                      </ul>
                    </div>

                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-6 mb-8">
                      <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-3">7.2 Original Logs & Zenodo Dataset</h5>
                      <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
                        For all the Research Questions (RQs), we provide the original logs that can be downloaded from Zenodo. You can access and download the dataset here:{' '}
                        <a 
                          href="https://zenodo.org/records/18389642" 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-indigo-600 dark:text-indigo-400 hover:underline font-medium"
                        >
                          https://zenodo.org/records/18389642
                        </a>
                      </p>
                      <div className="bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 rounded-lg p-4 mb-4 flex items-start gap-3 text-amber-800 dark:text-amber-200">
                        <Archive className="h-5 w-5 shrink-0 mt-0.5" />
                        <p className="text-sm">
                          <strong>Note on Storage:</strong> Downloading the complete dataset will take substantial space (<strong>~530GB</strong>). This dataset corresponds to the original logs and full packet capture files generated during the paper's experiments.
                        </p>
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-6">
                      <h5 className="font-semibold text-slate-900 dark:text-slate-100 mb-3">7.3 Reproduction Scripts</h5>
                      <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
                        Every reproduction script for the RQs is designed to work directly with the raw logs. 
                      </p>
                      <ul className="list-disc pl-5 space-y-2 text-sm text-slate-600 dark:text-slate-400">
                        <li><strong>Relative Paths:</strong> The scripts use relative paths, making them portable across different directory structures.</li>
                        <li><strong>No Hardcoded Values:</strong> The scripts dynamically parse the logs to generate custom plots, ensuring that there are no hardcoded metric values.</li>
                        <li><strong>Easily Customizable:</strong> You can easily modify the scripts to generate custom plots, filter specific data points, or adapt them to new log formats.</li>
                      </ul>
                    </div>

                  </div>
                </motion.div>
              )}

            </div>
          </div>
        </section>
        
        {/* Citation */}
        <section className="mt-24 rounded-2xl bg-slate-900 p-8 text-white sm:p-12">
          <h3 className="text-xl font-semibold mb-6">Citation</h3>
          <div className="relative rounded-lg bg-slate-800 p-4 font-mono text-sm text-slate-300 overflow-x-auto">
            <pre>
{`@inproceedings{benita2026oranclaw,
  title={ORANClaw: Shredding E2 Nodes in O-RAN via Structure-aware MiTM Fuzzing},
  author={Benita, Geovani and Garbelini, Matheus E. and Chattopadhyay, Sudipta and Zhou, Jianying},
  booktitle={Proceedings of the 19th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec '26)},
  year={2026}
}`}
            </pre>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 py-12">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-6 px-6 sm:flex-row">
          <div className="flex items-center gap-3 font-bold text-slate-900 dark:text-slate-100 text-lg">
            <img src={`${import.meta.env.BASE_URL}Logo.png`} alt="ORANClaw Logo" className="h-14 w-14 object-contain" />
            <span>ORANClaw</span>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            © {new Date().getFullYear()} ASSET Research Group. All rights reserved.
          </p>
          <div className="flex gap-4">
            <a href="#" className="text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 dark:text-slate-100">
              <Github className="h-5 w-5" />
            </a>
            <a href="#" className="text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 dark:text-slate-100">
              <ExternalLink className="h-5 w-5" />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
