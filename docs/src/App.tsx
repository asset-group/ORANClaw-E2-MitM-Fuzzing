/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Document, Page, pdfjs } from 'react-pdf';
import 'react-pdf/dist/Page/AnnotationLayer.css';
import 'react-pdf/dist/Page/TextLayer.css';

// Set up the worker for pdfjs - use local bundle to avoid CDN failures on mobile
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.mjs',
  import.meta.url,
).toString();

import { 
  Github, FileText, Activity, ExternalLink, BookOpen, 
  Terminal, Server, CheckCircle2, PlayCircle, Settings, BarChart,
  Folder, FileCode, Archive, ChevronLeft, ChevronRight, Zap, Search, ShieldAlert,
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

interface VulnEntry {
  impl: string; id: string; cve: string; vuln: string;
  cause: string; component: string; threat: string; location: string;
  structural?: boolean; existing?: boolean;
}

const vulnData: VulnEntry[] = [
  { impl: 'O-RAN SC RIC', id: 'VulnOSCRIC-01', cve: 'CVE-2025-67398', vuln: 'Unhandled Exception', cause: 'Flooding E2SetupRequest', component: 'E2 Termination', threat: 'DoS', location: 'Not Specified' },
  { impl: 'VIAVI TeraVM RSG', id: 'VulnVIAVI-01', cve: 'Pending', vuln: 'Heap/Stack Buffer Overflow', cause: 'Malformed RC SM Structure', component: 'gNB', threat: 'Mem. Corrupt', location: 'Not Specified', structural: true },
  { impl: 'VIAVI TeraVM RSG', id: 'VulnVIAVI-02', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'RIC', threat: 'DoS', location: 'nr-gnb-mac.cc:1136' },
  { impl: 'VIAVI TeraVM RSG', id: 'VulnVIAVI-03', cve: 'Pending', vuln: 'Unhandled Exception', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'DoS', location: 'Not Specified' },
  { impl: 'VIAVI TeraVM RSG', id: 'VulnVIAVI-04', cve: 'Pending', vuln: 'Buffer Over-read', cause: 'Malformed KPM SM Field', component: 'RIC', threat: 'Mem. Corrupt', location: 'Not Specified' },
  { impl: 'VIAVI TeraVM RSG', id: 'VulnVIAVI-05', cve: 'Pending', vuln: 'Unhandled Exception', cause: 'Malformed KPM SM Structure', component: 'GUI, gNB, RIC', threat: 'DoS', location: 'Not Specified', structural: true },
  { impl: 'OAI', id: 'VulnOAI-01', cve: 'CVE-2024-48408', vuln: 'Assertion', cause: 'Malformed MAC SM Field', component: 'O-DU', threat: 'DoS', location: 'ran_func_mac.c:126' },
  { impl: 'OAI', id: 'VulnOAI-02', cve: 'CVE-2025-52142', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'O-DU/CU-UP', threat: 'DoS', location: 'ran_func_kpm_subs.c:226' },
  { impl: 'OAI', id: 'VulnOAI-03', cve: 'CVE-2025-52146', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'O-DU/CU-UP', threat: 'DoS', location: 'msg_handler_agent.c:136' },
  { impl: 'OAI', id: 'VulnOAI-04', cve: 'CVE-2025-52150', vuln: 'Assertion', cause: 'Truncated MAC SM Structure', component: 'O-DU', threat: 'DoS', location: 'mac_dec_plain.c:190', structural: true },
  { impl: 'OAI', id: 'VulnOAI-05', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'O-DU', threat: 'DoS', location: 'ran_func_kpm.c:267/268' },
  { impl: 'OAI', id: 'VulnOAI-06', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Structure', component: 'O-DU', threat: 'DoS', location: 'ran_func_kpm.c:72', structural: true },
  { impl: 'OAI', id: 'VulnOAI-07', cve: 'CVE-2025-52148', vuln: 'Assertion', cause: 'Unexpected TC SM Field', component: 'O-CU-UP', threat: 'DoS', location: 'tc_dec_plain.c:1418' },
  { impl: 'OAI', id: 'VulnOAI-08', cve: 'CVE-2025-52151', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'O-CU-UP', threat: 'DoS', location: 'ran_func_kpm.c:230' },
  { impl: 'OAI', id: 'VulnOAI-09', cve: 'CVE-2025-52147', vuln: 'Assertion', cause: 'Zero-ed RC SM Field', component: 'O-CU-CP', threat: 'DoS', location: 'rc_dec_asn.c:953' },
  { impl: 'OAI', id: 'VulnOAI-10', cve: 'Pending', vuln: 'Assertion', cause: 'Unable To Recover', component: 'O-CU-CP (E1)', threat: 'DoS', location: 'cucp_cuup_e1ap.c:31' },
  { impl: 'OAI', id: 'VulnOAI-11', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Structure', component: 'O-CU-UP', threat: 'DoS', location: 'ran_func_kpm.c:177', structural: true },
  { impl: 'OAI', id: 'VulnOAI-12', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42RICsubscriptionDeleteRequest Field', component: 'O-CU-CP', threat: 'DoS', location: 'bimap.c:126' },
  { impl: 'OAI', id: 'VulnOAI-13', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'O-CU-UP', threat: 'DoS', location: 'ran_func_kpm.c:168' },
  { impl: 'OAI', id: 'VulnOAI-14', cve: 'Pending', vuln: 'Assertion', cause: 'Multiple Malformed KPM Fields', component: 'O-DU/CU-UP', threat: 'DoS', location: 'ran_func_kpm.c:71' },
  { impl: 'OAI', id: 'VulnOAI-15', cve: 'Pending', vuln: 'Assertion', cause: 'Invalid KPM SM Field', component: 'O-CU-CP/CU-UP', threat: 'DoS', location: 'ran_func_kpm.c:229' },
  { impl: 'OAI', id: 'VulnOAI-16', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'O-CU-CP/UP', threat: 'DoS', location: 'ran_func_kpm.c:176' },
  { impl: 'OAI', id: 'VulnOAI-17', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'O-CU-CP/UP', threat: 'DoS', location: 'ran_func_kpm.c:167' },
  { impl: 'OAI', id: 'VulnOAI-18', cve: 'Pending', vuln: 'Assertion', cause: 'Unable To Recover', component: 'O-CU-UP/CP', threat: 'DoS', location: 'e2_agent.c:242' },
  { impl: 'OAI', id: 'VulnOAI-19', cve: 'Pending', vuln: 'Assertion', cause: 'Invalid KPM SM Field', component: 'O-CU-UP/CP', threat: 'DoS', location: 'plugin_agent.c:286' },
  { impl: 'NS-3', id: 'VulnNS-01', cve: 'Pending', vuln: 'Buffer Overflow', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'Mem. Corrupt', location: 'Not Specified' },
  { impl: 'NS-3', id: 'VulnNS-02', cve: 'Pending', vuln: 'Heap-based Buffer Overflow', cause: 'Malformed E42SetupRequest Field', component: 'gNB', threat: 'Mem. Corrupt', location: 'Not Specified' },
  { impl: 'NS-3', id: 'VulnNS-03', cve: 'Pending', vuln: 'Heap-Based Buffer Overflow', cause: 'E42SetupRequest Duplication', component: 'gNB', threat: 'Mem. Corrupt', location: 'Not Specified' },
  { impl: 'NS-3', id: 'VulnNS-04', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42RICSubscriptionDeleteRequest', component: 'gNB', threat: 'DoS', location: 'ipv4-l3-protocol.cc:972' },
  { impl: 'NS-3', id: 'VulnNS-05', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'DoS', location: 'ipv4-l3-protocol.cc:580' },
  { impl: 'NS-3', id: 'VulnNS-06', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed RICSubscriptionRequest Field', component: 'LTE eNB', threat: 'DoS', location: 'lte-spectrum-phy.cc:486' },
  { impl: 'NS-3', id: 'VulnNS-07', cve: 'Pending', vuln: 'Null pointer dereference', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'Mem. Corrupt', location: 'ptr.h:638' },
  { impl: 'NS-3', id: 'VulnNS-08', cve: 'Pending', vuln: 'Out-of-bounds read', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'Info. Disclosure', location: 'net-device-queue-interface.cc:216' },
  { impl: 'NS-3', id: 'VulnNS-09', cve: 'Pending', vuln: 'Null pointer dereference', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'Mem. Corrupt', location: 'ptr.h:630' },
  { impl: 'NS-3', id: 'VulnNS-10', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'DoS', location: 'object.cc:349' },
  { impl: 'NS-3', id: 'VulnNS-11', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed RICSubscriptionRequest Field', component: 'gNB', threat: 'DoS', location: 'traffic-control-layer.cc:337' },
  { impl: 'NS-3', id: 'VulnNS-12', cve: 'Pending', vuln: 'Improper Input Validation', cause: 'Malformed E42RICSubscriptionDeleteRequest Field', component: 'gNB', threat: 'DoS', location: 'point-to-point-net-device.cc:279' },
  { impl: 'NS-3', id: 'VulnNS-13', cve: 'Pending', vuln: 'Improper Check for Unusual/Exceptional Conditions', cause: 'Malformed E42RICSubscriptionDeleteRequest Field', component: 'gNB', threat: 'Improper File Handling', location: 'mmwave-phy-trace.cc:399' },
  { impl: 'NS-3', id: 'VulnNS-14', cve: 'Pending', vuln: 'Assertion', cause: 'Invalid KPM RC Field', component: 'gNB', threat: 'DoS', location: 'default-simulator-impl.cc:235' },
  { impl: 'NS-3', id: 'VulnNS-15', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed RICcontrolRequest Field', component: 'gNB', threat: 'DoS', location: 'buffer.cc:183' },
  { impl: 'NS-3', id: 'VulnNS-16', cve: 'Pending', vuln: 'Improper Input Validation', cause: 'Malformed E42RICSubscriptionDeleteRequest Field', component: 'gNB', threat: 'DoS', location: 'mmwave-phy-trace.cc:220' },
  { impl: 'NS-3', id: 'VulnNS-17', cve: 'Pending', vuln: 'Improper Check for Unusual/Exceptional Conditions', cause: 'Malformed E42RICSubscriptionDeleteRequest Field', component: 'gNB', threat: 'Improper File Handling', location: 'mmwave-phy-trace.cc:71' },
  { impl: 'NS-3', id: 'VulnNS-18', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed RICSubscriptionRequest Field', component: 'LTE eNB', threat: 'DoS', location: 'mmwave-enb-phy.cc:1141' },
  { impl: 'FlexRIC', id: '—', cve: 'CVE-2024-34034', vuln: 'Assertion', cause: 'Flooding E42SubscriptionRequest', component: 'RIC', threat: 'DoS', location: 'Not Specified', existing: true },
  { impl: 'FlexRIC', id: 'VulnFlex-01', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed RICSubscriptionRequest Field', component: 'RIC', threat: 'DoS', location: 'msg_handler_iapp.c:343' },
  { impl: 'FlexRIC', id: 'VulnFlex-02', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42RICsubscriptionDelete Fields', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:2534' },
  { impl: 'FlexRIC', id: 'VulnFlex-03', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Fields', component: 'RIC', threat: 'DoS', location: 'msg_handler_ric.c:117' },
  { impl: 'FlexRIC', id: 'VulnFlex-04', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Fields', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:544' },
  { impl: 'FlexRIC', id: 'VulnFlex-05', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:487' },
  { impl: 'FlexRIC', id: 'VulnFlex-06', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed MAC SM Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:1107' },
  { impl: 'FlexRIC', id: 'VulnFlex-07', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionDelete Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:2523' },
  { impl: 'FlexRIC', id: 'VulnFlex-08', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionDelete Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:2540' },
  { impl: 'FlexRIC', id: 'VulnFlex-09', cve: 'Pending', vuln: 'Assertion', cause: 'Flooding E42SetupRequest', component: 'RIC', threat: 'DoS', location: 'e2ap_msg_enc_asn.c:3165' },
  { impl: 'FlexRIC', id: 'VulnFlex-10', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:536' },
  { impl: 'FlexRIC', id: 'VulnFlex-11', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionDeleteRequest Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:2531' },
  { impl: 'FlexRIC', id: 'VulnFlex-12', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:527' },
  { impl: 'FlexRIC', id: 'VulnFlex-13', cve: 'Pending', vuln: 'Assertion', cause: 'E42SubscriptionDeleteRequest Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:2548' },
  { impl: 'FlexRIC', id: 'VulnFlex-14', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v2.03)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:477' },
  { impl: 'FlexRIC', id: 'VulnFlex-15', cve: 'Pending', vuln: 'Assertion', cause: 'Unable to Recover', component: 'RIC', threat: 'DoS', location: 'map_e2_node_sockaddr.c:154' },
  { impl: 'FlexRIC', id: 'VulnFlex-16', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed KPM SM Field', component: 'RIC', threat: 'DoS', location: 'reg_e2_nodes.c:174' },
  { impl: 'FlexRIC', id: 'VulnFlex-17', cve: 'Pending', vuln: 'Assertion', cause: 'Unable to Recover', component: 'RIC', threat: 'DoS', location: 'map_ric_id.c:227' },
  { impl: 'FlexRIC', id: 'VulnFlex-18', cve: 'Pending', vuln: 'Assertion', cause: 'Unable to Recover', component: 'RIC', threat: 'DoS', location: 'assoc_rb_tree.c:457' },
  { impl: 'FlexRIC', id: 'VulnFlex-19', cve: 'Pending', vuln: 'Assertion', cause: 'Flooding E42SubscriptionRequest', component: 'RIC', threat: 'DoS', location: 'msg_handler_iapp.c:342' },
  { impl: 'FlexRIC', id: 'VulnFlex-20', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:418' },
  { impl: 'FlexRIC', id: 'VulnFlex-21', cve: 'Pending', vuln: 'Assertion', cause: 'E42SubscriptionDeleteRequest Field', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:435' },
  { impl: 'FlexRIC', id: 'VulnFlex-22', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:378' },
  { impl: 'FlexRIC', id: 'VulnFlex-23', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:368' },
  { impl: 'FlexRIC', id: 'VulnFlex-24', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SetupRequest Field', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:2113' },
  { impl: 'FlexRIC', id: 'VulnFlex-25', cve: 'Pending', vuln: 'Assertion', cause: 'Unable To Recover', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_enc_asn.c:2731' },
  { impl: 'FlexRIC', id: 'VulnFlex-26', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SubscriptionRequest Field', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:427' },
  { impl: 'FlexRIC', id: 'VulnFlex-27', cve: 'Pending', vuln: 'Assertion', cause: 'Malformed E42SetupRequest Field', component: 'RIC E2AP(v1.01)', threat: 'DoS', location: 'e2ap_msg_dec_asn.c:2101' },
  { impl: 'FlexRIC', id: 'VulnFlex-28', cve: 'Pending', vuln: 'Assertion', cause: 'Unable To Recover', component: 'RIC', threat: 'DoS', location: 'endpoint_ric.c:64' },
];

const implGroups = ['O-RAN SC RIC', 'VIAVI TeraVM RSG', 'OAI', 'NS-3', 'FlexRIC'];

const implColors: Record<string, string> = {
  'O-RAN SC RIC': 'bg-violet-100 text-violet-800 dark:bg-violet-900/30 dark:text-violet-300 border-violet-200 dark:border-violet-800',
  'VIAVI TeraVM RSG': 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800',
  'OAI': 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800',
  'NS-3': 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300 border-orange-200 dark:border-orange-800',
  'FlexRIC': 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300 border-indigo-200 dark:border-indigo-800',
};

const threatColors: Record<string, string> = {
  'DoS': 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  'Mem. Corrupt': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  'Info. Disclosure': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  'Improper File Handling': 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
};

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
      'push', 'iperf3',
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
  const [activeImplFilter, setActiveImplFilter] = useState('All');

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
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 sm:px-6 sm:py-4">
          <div className="flex items-center gap-2 sm:gap-3 font-bold tracking-tight text-slate-900 dark:text-white text-lg sm:text-xl">
            <img src={`${import.meta.env.BASE_URL}Logo.png`} alt="ORANClaw Logo" className="h-10 w-10 sm:h-16 sm:w-16 object-contain" />
            <span>ORANClaw</span>
          </div>
          <div className="hidden items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-400 sm:flex">
            <a href="#overview" className="hover:text-indigo-600 dark:text-indigo-400 dark:hover:text-indigo-400 transition-colors">Overview</a>
            <a href="#vulnerabilities" className="hover:text-red-600 dark:hover:text-red-400 transition-colors">Vulnerabilities</a>
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
              href="https://github.com/asset-group/ORANClaw-E2-MitM-Fuzzing" 
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
      <header className="relative overflow-hidden bg-white dark:bg-slate-950 px-6 py-12 sm:py-24 md:py-32">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]"></div>
        <div className="relative mx-auto max-w-5xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="flex justify-center mb-8">
              <img src={`${import.meta.env.BASE_URL}Logo.png`} alt="ORANClaw Logo" className="h-28 sm:h-44 md:h-56 w-auto object-contain drop-shadow-xl dark:drop-shadow-[0_20px_20px_rgba(255,255,255,0.05)]" />
            </div>
            <h3 className="font-serif text-3xl font-semibold tracking-tight text-slate-900 dark:text-white sm:text-4xl">
              ORANClaw<br className="hidden sm:block" />
              <span className="text-indigo-600 dark:text-indigo-400">Giving E2 nodes a Bad Day via Structure-Aware MiTM Fuzzing</span>
            </h3>
            <p className="mx-auto mt-8 max-w-2xl text-lg leading-relaxed text-slate-600 dark:text-slate-400">
              A structure-aware, man-in-the-middle fuzzing framework that takes full control over the E2 interface between the NearRT-RIC and the gNB (E2 nodes) to systematically mutate packets and disrupt base station behavior.
              {' '}Across 5 O-RAN implementations, it uncovered <span className="font-semibold text-slate-800 dark:text-slate-200">71 new vulnerabilities</span> — 1 in O-RAN SC RIC, 5 in VIAVI TeraVM RSG, 19 in OpenAirInterface, 18 in ns-3, and 28 in FlexRIC.
            </p>
            <div className="flex flex-wrap justify-center items-center gap-6 sm:gap-10 mt-10">
              <img src={`${import.meta.env.BASE_URL}artifacts_available.png`} alt="Artifacts Available" className="h-20 sm:h-24 w-auto object-contain drop-shadow-sm" />
              <img src={`${import.meta.env.BASE_URL}artifacts_evaluated_functional.png`} alt="Artifacts Evaluated – Functional" className="h-20 sm:h-24 w-auto object-contain drop-shadow-sm" />
              <img src={`${import.meta.env.BASE_URL}results_replicated.png`} alt="Results Replicated" className="h-20 sm:h-24 w-auto object-contain drop-shadow-sm" />
            </div>
          </motion.div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-16 sm:py-24">
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
                Operating as a Man-in-the-Middle (MiTM) proxy on the E2 interface, ORANClaw intercepts and intelligently mutates live E2 Application Protocol (E2AP) messages exchanged between the Near-Real-Time RAN Intelligent Controller (Near-RT RIC) and E2 Nodes (O-CU, O-DU). By leveraging ASN.1 structural awareness, it dynamically injects malformed yet structurally valid payloads directly into the communication stream. This allows ORANClaw to bypass initial parsing checks and effectively expose deep-seated vulnerabilities and bugs within O-RAN components that traditional, structure-blind fuzzers fail to reach.
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

          <div className="flex flex-col gap-6">
            {/* Horizontal Tab Bar */}
            <div className="flex flex-wrap gap-1.5 sm:gap-2 sticky top-14 sm:top-20 z-40 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl px-2 sm:px-3 py-2 sm:py-2.5 shadow-sm">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => { setActiveTab(tab.id); document.getElementById('reproducibility')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }}
                  className={`flex items-center gap-1.5 rounded-xl px-3 py-2 text-xs sm:text-sm sm:px-4 sm:py-2.5 font-medium transition-all ${
                    activeTab === tab.id
                      ? 'bg-indigo-600 dark:bg-indigo-500 text-white shadow-md shadow-indigo-200 dark:shadow-none'
                      : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100'
                  }`}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="min-h-[600px] rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 sm:p-10 shadow-sm">
              
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
git clone https://github.com/asset-group/ORANClaw-E2-MitM-Fuzzing.git
cd $HOME/ORANClaw-E2-MitM-Fuzzing`} />
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
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing
wget -O vakt-ble-defender.zip https://zenodo.org/records/18368683/files/vakt-ble-defender.zip?download=1
unzip vakt-ble-defender
rm -rf vakt-ble-defender.zip

cd $HOME/ORANClaw-E2-MitM-Fuzzing/asn1
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
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing
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
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing/scripts/
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
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing/
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
                        <CodeBlock title="UE to Core Network" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing/
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
                        <CodeBlock title="Launch the fuzzer" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing/asn1
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
                        <CodeBlock title="Start xApp KPI monitoring" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing/
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
                        <CodeBlock code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing/
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
                        <CodeBlock title="Regenerate encoder and decoder" code={`cd $HOME/ORANClaw-E2-MitM-Fuzzing/
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

              {/* Prev / Next navigation */}
              {(() => {
                const currentIndex = tabs.findIndex(t => t.id === activeTab);
                const prevTab = tabs[currentIndex - 1];
                const nextTab = tabs[currentIndex + 1];
                return (
                  <div className="flex items-center justify-between pt-8 mt-8 border-t border-slate-200 dark:border-slate-800">
                    {prevTab ? (
                      <button
                        onClick={() => { setActiveTab(prevTab.id); document.getElementById('reproducibility')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }}
                        className="flex items-center gap-2 text-sm font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 transition-colors"
                      >
                        <ChevronLeft className="h-4 w-4" />
                        {prevTab.label}
                      </button>
                    ) : <div />}
                    <span className="text-xs text-slate-400 dark:text-slate-600">{currentIndex + 1} / {tabs.length}</span>
                    {nextTab ? (
                      <button
                        onClick={() => { setActiveTab(nextTab.id); document.getElementById('reproducibility')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }}
                        className="flex items-center gap-2 text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 transition-colors"
                      >
                        {nextTab.label}
                        <ChevronRight className="h-4 w-4" />
                      </button>
                    ) : <div />}
                  </div>
                );
              })()}
            </div>
          </div>
        </section>
        
        {/* Vulnerabilities Section */}
        <section id="vulnerabilities" className="scroll-mt-24 mt-16 mb-16 sm:mt-24 sm:mb-24">
          <div className="mb-10">
            <h2 className="text-sm font-bold uppercase tracking-widest text-red-600 dark:text-red-400">03 / Security Findings</h2>
            <h3 className="mt-2 text-2xl sm:text-3xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">Discovered Vulnerabilities</h3>
            <p className="mt-4 text-slate-600 dark:text-slate-400 max-w-3xl">
              Complete table of vulnerabilities discovered by ORANClaw across all tested O-RAN implementations.
              Causes in <strong className="text-slate-800 dark:text-slate-200">bold</strong> indicate structural message mutations rather than single-field modifications.
              <em> "Unable To Recover"</em> denotes failures to restore normal operation from crashes in previous sessions.
            </p>
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 sm:gap-3 mb-8">
            {implGroups.map(impl => {
              const count = vulnData.filter(v => v.impl === impl).length;
              const colors = implColors[impl];
              return (
                <button
                  key={impl}
                  onClick={() => setActiveImplFilter(activeImplFilter === impl ? 'All' : impl)}
                  className={`rounded-xl border p-4 text-left transition-all hover:scale-[1.02] ${activeImplFilter === impl ? colors + ' ring-2 ring-offset-2 ring-offset-slate-50 dark:ring-offset-slate-950' : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400'}`}
                >
                  <div className="text-2xl font-bold">{count}</div>
                  <div className="text-xs font-medium mt-1 leading-tight">{impl}</div>
                </button>
              );
            })}
          </div>

          {/* Filter bar */}
          <div className="flex flex-wrap gap-2 mb-6">
            {['All', ...implGroups].map(f => (
              <button
                key={f}
                onClick={() => setActiveImplFilter(f)}
                className={`rounded-full px-4 py-1.5 text-xs font-semibold transition-colors ${activeImplFilter === f ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'}`}
              >
                {f} {f !== 'All' && `(${vulnData.filter(v => v.impl === f).length})`}
                {f === 'All' && `(${vulnData.length})`}
              </button>
            ))}
          </div>

          {/* Table */}
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
            <table className="text-xs min-w-[640px] w-full">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700 text-left">
                  <th className="px-3 py-3 font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">VulnID</th>
                  <th className="px-3 py-3 font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">CVE</th>
                  <th className="px-3 py-3 font-semibold text-slate-700 dark:text-slate-300">Vulnerability</th>
                  <th className="px-3 py-3 font-semibold text-slate-700 dark:text-slate-300">General Cause</th>
                  <th className="px-3 py-3 font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">Component</th>
                  <th className="px-3 py-3 font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">Threat</th>
                  <th className="px-3 py-3 font-semibold text-slate-700 dark:text-slate-300">Location</th>
                </tr>
              </thead>
              <tbody>
                {(() => {
                  const filtered = activeImplFilter === 'All' ? vulnData : vulnData.filter(v => v.impl === activeImplFilter);
                  const rows: React.ReactNode[] = [];
                  let lastImpl = '';
                  filtered.forEach((v, i) => {
                    if (v.impl !== lastImpl) {
                      lastImpl = v.impl;
                      const colors = implColors[v.impl] || '';
                      rows.push(
                        <tr key={`group-${v.impl}`} className={`border-b border-slate-100 dark:border-slate-800 ${colors.split(' ').filter(c => c.startsWith('bg-') || c.startsWith('dark:bg-')).join(' ')}`}>
                          <td colSpan={7} className="px-4 py-2">
                            <span className={`inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider ${colors.split(' ').filter(c => c.startsWith('text-') || c.startsWith('dark:text-')).join(' ')}`}>
                              <ShieldAlert className="h-3.5 w-3.5" />
                              {v.impl}
                            </span>
                          </td>
                        </tr>
                      );
                    }
                    rows.push(
                      <tr key={i} className={`border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors ${v.existing ? 'opacity-60' : ''}`}>
                        <td className="px-3 py-2.5 align-top font-mono font-medium text-slate-700 dark:text-slate-300 whitespace-nowrap leading-snug">
                          {v.id}
                          {v.existing && <span className="ml-1 text-[10px] bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 rounded px-1 py-0.5">existing</span>}
                        </td>
                        <td className="px-3 py-2.5 align-top leading-snug whitespace-nowrap">
                          {v.cve.startsWith('CVE-') ? (
                            <a href={`https://nvd.nist.gov/vuln/detail/${v.cve}`} target="_blank" rel="noopener noreferrer"
                              className="text-indigo-600 dark:text-indigo-400 hover:underline font-mono font-medium">
                              {v.cve}
                            </a>
                          ) : (
                            <span className="text-slate-400 dark:text-slate-500 italic">{v.cve}</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 align-top text-slate-600 dark:text-slate-400 leading-snug min-w-[140px]">{v.vuln}</td>
                        <td className="px-3 py-2.5 align-top text-slate-700 dark:text-slate-300 leading-snug min-w-[140px]">
                          {v.structural ? <strong>{v.cause}</strong> : v.cause}
                        </td>
                        <td className="px-3 py-2.5 align-top font-mono text-slate-600 dark:text-slate-400 leading-snug whitespace-nowrap">{v.component}</td>
                        <td className="px-3 py-2.5 align-top whitespace-nowrap">
                          <span className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold leading-snug ${threatColors[v.threat] || 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'}`}>
                            {v.threat}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 align-top font-mono text-[10px] text-slate-500 dark:text-slate-500 whitespace-nowrap leading-snug">{v.location}</td>
                      </tr>
                    );
                  });
                  return rows;
                })()}
              </tbody>
            </table>
            </div>
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-3">
            * CVE links open the NVD entry. "Pending" entries are under coordinated disclosure. Bold causes = structural mutations.
          </p>
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
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-6 px-6 sm:flex-row">
          <div className="flex items-center gap-3 font-bold text-slate-900 dark:text-slate-100 text-lg">
            <img src={`${import.meta.env.BASE_URL}Logo.png`} alt="ORANClaw Logo" className="h-14 w-14 object-contain" />
            <span>ORANClaw</span>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            © {new Date().getFullYear()} ASSET Research Group. All rights reserved.
          </p>
          <div className="flex gap-4">
            <a href="https://github.com/asset-group/ORANClaw-E2-MitM-Fuzzing" target="_blank" rel="noreferrer" className="text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 dark:text-slate-100">
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
