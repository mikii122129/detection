#!/usr/bin/env python3

import os
import glob
import re
import logging
import time
import math
import random
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from torch.optim.lr_scheduler import ReduceLROnPlateau
from transformers import AutoTokenizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.utils.class_weight import compute_class_weight
from collections import deque
from dataclasses import dataclass
from typing import List, Dict
import requests

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class OWASPLabelMapping:
    LABEL_TO_OWASP = {
        0: 'Benign',
        1: 'A01-BrokenAccessControl',
        2: 'A02-SecurityMisconfiguration',
        3: 'A03-SoftwareSupplyChainFailures',
        4: 'A04-CryptographicFailures',
        5: 'A05-Injection',
        6: 'A06-InsecureDesign',
        7: 'A07-AuthenticationFailures',
        8: 'A08-SoftwareDataIntegrityFailures',
        9: 'A09-SecurityLoggingAlertingFailures',
        10: 'A10-MishandlingExceptionalConditions'
    }

@dataclass
class Config:
    vocab_size: int = 30522
    embedding_dim: int = 128
    hidden_dim: int = 256
    num_layers: int = 2
    bidirectional: bool = True
    num_labels: int = 11
    max_length: int = 128
    batch_size: int = 64
    epochs: int = 8
    lr: float = 1e-3
    device: str = "cpu"
    replay_buffer_size: int = 2000
    ewc_lambda: float = 0.5
    lwf_lambda: float = 1.0

# --- 1. Advanced Feature Engineering ---

def calculate_entropy(string):
    """Calculates Shannon Entropy to detect obfuscated strings."""
    if not string: return 0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def extract_url_features(url: str) -> np.ndarray:
    if not url: return np.zeros(32, dtype=np.float32)
    features = []
    text = url.lower()
    
    # Structural features
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('/'))
    features.append(url.count('='))
    features.append(url.count('?'))
    
    # NEW: Entropy feature (High entropy = suspicious/obfuscated)
    features.append(calculate_entropy(text))
    
    # Keyword Heuristics
    features.append(1 if re.search(r'(union|select|script|alert|onerror)', text) else 0)
    features.append(1 if re.search(r'(admin|login|dashboard|config|token)', text) else 0)
    features.append(1 if re.search(r'(http:|https:|ftp:|localhost|\:\d+)', text) else 0)
    features.append(1 if re.search(r'(id=\d+|object|serialize|file=)', text) else 0)
    features.append(1 if re.search(r'(password|credit_card|ssn|secret)', text) else 0)
    
    while len(features) < 32: features.append(0)
    return np.array(features[:32], dtype=np.float32)

# --- 2. Dataset ---

class TrafficDataset(Dataset):
    def __init__(self, requests_list: List[str], labels: List[int], tokenizer, max_length=128):
        self.requests = requests_list
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self): return len(self.labels)

    def __getitem__(self, idx):
        text = str(self.requests[idx])
        features = extract_url_features(text)
        encoded = self.tokenizer(text, truncation=True, padding='max_length', 
                                 max_length=self.max_length, return_tensors='pt')
        return {
            'input_ids': encoded['input_ids'].squeeze(0),
            'log_features': torch.tensor(features, dtype=torch.float),
            'labels': torch.tensor(self.labels[idx], dtype=torch.long)
        }

# --- 3. Model with Attention ---

class BiLSTMModel(nn.Module):
    def __init__(self, config: Config):
        super().__init__()
        self.embedding = nn.Embedding(config.vocab_size, config.embedding_dim)
        self.lstm = nn.LSTM(config.embedding_dim, config.hidden_dim, 
                           num_layers=config.num_layers, bidirectional=config.bidirectional,
                           batch_first=True, dropout=0.3)
        
        # Attention Layer
        self.attention = nn.Linear(config.hidden_dim * 2, 1)
        
        self.log_projector = nn.Sequential(nn.Linear(32, config.hidden_dim), nn.ReLU(), nn.Dropout(0.3))
        
        lstm_output_dim = config.hidden_dim * 2
        self.classifier = nn.Sequential(
            nn.Linear(lstm_output_dim + config.hidden_dim, config.hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(config.hidden_dim, config.num_labels)
        )

    def forward(self, input_ids, log_features):
        embeds = self.embedding(input_ids)  # [batch, seq_len, emb_dim]
        lstm_out, _ = self.lstm(embeds)     # [batch, seq_len, hid_dim*2]
        
        # Attention Mechanism
        attn_weights = F.softmax(self.attention(lstm_out), dim=1) # [batch, seq_len, 1]
        context = torch.sum(attn_weights * lstm_out, dim=1)       # [batch, hid_dim*2]
        
        log_proj = self.log_projector(log_features)
        fused = torch.cat([context, log_proj], dim=1)
        return self.classifier(fused)

# --- 4. Adaptive Components ---

class ReplayBuffer:
    def __init__(self, max_size): self.buffer = deque(maxlen=max_size)
    def add(self, sample): self.buffer.append(sample)
    def sample(self, n):
        if len(self.buffer) < n: return []
        idx = np.random.choice(len(self.buffer), n, replace=False)
        return [self.buffer[i] for i in idx]

class EWC:
    def __init__(self, model, device):
        self.model = model; self.device = device; self.fisher = {}; self.optimal = {}; self.initialized = False
    def compute_fisher(self, loader, criterion):
        logger.info("Computing Fisher Information (EWC)...")
        self.model.eval()
        self.fisher = {n: torch.zeros_like(p, device=self.device) for n, p in self.model.named_parameters() if p.requires_grad}
        for batch in loader:
            self.model.zero_grad()
            out = self.model(batch['input_ids'].to(self.device), batch['log_features'].to(self.device))
            loss = criterion(out, batch['labels'].to(self.device))
            loss.backward()
            for n, p in self.model.named_parameters():
                if p.grad is not None: self.fisher[n] += p.grad.data ** 2
        for n in self.fisher: self.fisher[n] /= len(loader)
        self.optimal = {n: p.clone().detach() for n, p in self.model.named_parameters() if p.requires_grad}
        self.initialized = True
    def penalty(self, lambda_ewc):
        if not self.initialized: return torch.tensor(0.0, device=self.device)
        loss = 0.0
        for n, p in self.model.named_parameters():
            if n in self.fisher: loss += (self.fisher[n] * (p - self.optimal[n]) ** 2).sum()
        return lambda_ewc * loss

class LwF:
    def __init__(self, temperature=2.0): self.temperature = temperature; self.old_state = None
    def store(self, model): self.old_state = {k: v.clone().detach() for k, v in model.state_dict().items()}
    def loss(self, model, input_ids, log_features, lambda_lwf):
        if self.old_state is None: return torch.tensor(0.0, device=input_ids.device)
        old_model = BiLSTMModel(Config()); old_model.load_state_dict(self.old_state); old_model.eval().to(input_ids.device)
        with torch.no_grad(): old_out = old_model(input_ids, log_features)
        new_out = model(input_ids, log_features)
        old_p = F.softmax(old_out / self.temperature, dim=1)
        new_logp = F.log_softmax(new_out / self.temperature, dim=1)
        return lambda_lwf * F.kl_div(new_logp, old_p, reduction='batchmean') * (self.temperature ** 2)

class WebsiteScanner:
    def scan(self, domain: str) -> List[Dict]:
        findings = []; url = domain if domain.startswith('http') else f"http://{domain}"
        try:
            resp = requests.get(url, timeout=5, verify=False); headers = resp.headers
            if not url.startswith("https"): findings.append({'cat': 'A04', 'msg': 'No HTTPS'})
            if 'Strict-Transport-Security' not in headers: findings.append({'cat': 'A04', 'msg': 'Missing HSTS'})
            for h in ['X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options']:
                if h not in headers: findings.append({'cat': 'A02', 'msg': f'Missing {h}'})
            server = headers.get('Server', '')
            if re.search(r'\d', server): findings.append({'cat': 'A03', 'msg': f'Version Exposed: {server}'})
        except Exception as e: findings.append({'cat': 'A10', 'msg': f'Connection Failed: {e}'})
        return findings

# --- 5. Main System ---

class OWASPSystem:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.model = BiLSTMModel(self.config).to(self.config.device)
        self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        self.scanner = WebsiteScanner()
        self.replay_buffer = ReplayBuffer(self.config.replay_buffer_size)
        self.ewc = EWC(self.model, self.config.device)
        self.lwf = LwF()
        self.optimizer = AdamW(self.model.parameters(), lr=self.config.lr)
        self.scheduler = ReduceLROnPlateau(self.optimizer, mode='max', factor=0.5, patience=1)
        self.criterion = nn.CrossEntropyLoss()
        
    # --- DATA LOADING ---
    def load_data(self, paths: Dict[str, str]):
        texts, labels = [], []
        
        # 1. CSIC
        try:
            logger.info(f"Loading CSIC: {paths['csic']}")
            df = pd.read_csv(paths['csic'])
            url_col = next((c for c in df.columns if 'url' in c.lower() or 'path' in c.lower()), None)
            label_col = next((c for c in df.columns if 'label' in c.lower() or 'class' in c.lower()), None)
            if url_col and label_col:
                for _, r in df.iterrows():
                    texts.append(str(r[url_col])); labels.append(self._map_label(r[label_col]))
        except: pass

        # 2. CIC-IDS2017 (Randomized)
        try:
            logger.info(f"Loading CIC-IDS2017: {paths['cic']}")
            df_cic = pd.read_csv(paths['cic'])
            df_cic.columns = [c.strip() for c in df_cic.columns]
            
            users = ['admin', 'root', 'test', 'user1', 'manager']
            paths_login = ['/login', '/signin', '/auth', '/admin/login']
            
            for _, r in df_cic.iterrows():
                lbl = str(r['Label']).lower()
                if 'brute force' in lbl:
                    t = f"POST {random.choice(paths_login)}?user={random.choice(users)}&pass=pass123 HTTP/1.1"
                    texts.append(t); labels.append(7)
                elif 'sql injection' in lbl:
                    texts.append("GET /item?id=1' OR '1'='1"); labels.append(3)
                elif 'xss' in lbl:
                    texts.append("GET /search?q=<script>alert(1)</script>"); labels.append(3)
                elif 'benign' in lbl and np.random.rand() > 0.98:
                    texts.append("GET /index.html"); labels.append(0)
        except: pass

        # 3. PayloadsAllTheThings
        try:
            logger.info(f"Scanning Payloads: {paths['payloads_folder']}")
            folder_map = {'SQL Injection': 5, 'XSS': 5, 'SSRF': 1, 'Local File Inclusion': 1, 'CSRF': 1}
            for folder_name, label_id in folder_map.items():
                target_folder = os.path.join(paths['payloads_folder'], folder_name)
                if os.path.exists(target_folder):
                    files = glob.glob(os.path.join(target_folder, '**', '*.txt'), recursive=True)
                    for f in files:
                        try:
                            with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                                for line in file:
                                    if len(line) > 5:
                                        texts.append(f"GET /search?q={line.strip()}"); labels.append(label_id)
                        except: continue
        except: pass

        # 4. WebGoat
        webgoat_synth = [
            ("GET /WebGoat/Crypto?enc=weak", 4), ("POST /WebGoat/Deserialize", 8)
        ]
        for t, l in webgoat_synth: texts.extend([t] * 50); labels.extend([l] * 50)

        # 5. Gap Filling
        logger.info("Ensuring full coverage...")
        synth = [
            ("GET /admin HTTP/1.1", 1), ("GET /.env HTTP/1.1", 2), 
            ("GET /cgi-bin/test-cgi", 3), ("POST /login", 7),
            ("GET /debug", 10), ("GET /proxy?url=http://...", 1),
            ("GET /index.html", 0)
        ]
        for t, l in synth: texts.extend([t] * 200); labels.extend([l] * 200)
        
        logger.info(f"Total samples: {len(texts)}")
        return texts, labels

    def _map_label(self, raw):
        r = str(raw).lower()
        if r in ['normal', 'benign', '0', 'valid']: return 0
        if r in ['broken access control', 'brokenaccesscontrol', 'csrf', 'ssrf', 'server side request forgery']: return 1
        if r in ['security misconfiguration', 'misconfiguration', 'config exposure']: return 2
        if r in ['vulnerable and outdated components', 'vulnerableoutdatedcomponents', 'outdated components', 'software supply chain failures', 'supply chain']: return 3
        if r in ['cryptographic failures', 'cryptographicfailures', 'weak crypto', 'weak tls']: return 4
        if r in ['sql injection', 'sqli', 'xss', 'injection', 'command injection']: return 5
        if r in ['insecure design', 'insecuredesign']: return 6
        if r in ['identification and authentication failures', 'identificationauthfailures', 'authentication failures', 'auth failures', 'brute force']: return 7
        if r in ['software and data integrity failures', 'softwaredataintegrityfailures', 'deserialization', 'insecure deserialization']: return 8
        if r in ['security logging and monitoring failures', 'securityloggingmonitoringfailures', 'security logging and alerting failures']: return 9
        if r in ['mishandling of exceptional conditions', 'exceptional conditions', 'debug exposure']: return 10
        return 5

    # --- TRAINING ---
    def train_initial(self, texts, labels):
        unique_classes = np.unique(labels)
        weights = compute_class_weight('balanced', classes=unique_classes, y=labels)
        class_w = np.ones(self.config.num_labels)
        for i, c in enumerate(unique_classes): class_w[c] = weights[i]
        self.criterion = nn.CrossEntropyLoss(weight=torch.tensor(class_w, dtype=torch.float, device=self.config.device))

        train_t, test_t, train_l, test_l = train_test_split(texts, labels, test_size=0.2, random_state=42)
        train_ds = TrafficDataset(train_t, train_l, self.tokenizer, self.config.max_length)
        train_loader = DataLoader(train_ds, batch_size=self.config.batch_size, shuffle=True)
        
        logger.info("Starting Optimized Training...")
        best_acc = 0.0
        
        for epoch in range(self.config.epochs):
            self.model.train()
            total_loss = 0
            for batch in train_loader:
                self.optimizer.zero_grad()
                out = self.model(batch['input_ids'].to(self.config.device), batch['log_features'].to(self.config.device))
                loss = self.criterion(out, batch['labels'].to(self.config.device))
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item()
            
            # Validation
            self.model.eval()
            preds, true = [], []
            with torch.no_grad():
                for b in train_loader:
                    out = self.model(b['input_ids'].to(self.config.device), b['log_features'].to(self.config.device))
                    preds.extend(torch.argmax(out, dim=1).cpu().numpy())
                    true.extend(b['labels'].numpy())
            
            acc = accuracy_score(true, preds)
            self.scheduler.step(acc)
            
            logger.info(f"Epoch {epoch+1}/{self.config.epochs} | Loss: {total_loss/len(train_loader):.4f} | Acc: {acc*100:.2f}%")
            
            if acc > best_acc: best_acc = acc

        print("\n" + "="*60); print("     FINAL MODEL EVALUATION"); print("="*60)
        test_ds = TrafficDataset(test_t, test_l, self.tokenizer, self.config.max_length)
        test_loader = DataLoader(test_ds, batch_size=self.config.batch_size)
        self.model.eval(); preds, true = [], []
        with torch.no_grad():
            for b in test_loader:
                out = self.model(b['input_ids'].to(self.config.device), b['log_features'].to(self.config.device))
                preds.extend(torch.argmax(out, dim=1).cpu().numpy())
                true.extend(b['labels'].numpy())
        
        final_acc = accuracy_score(true, preds)
        print(f"Final Test Accuracy: {final_acc*100:.2f}%")
        target_names = list(OWASPLabelMapping.LABEL_TO_OWASP.values())
        labels_range = list(range(len(target_names)))
        print(classification_report(true, preds, labels=labels_range, target_names=target_names, zero_division=0))
        
        self.ewc.compute_fisher(train_loader, self.criterion)
        self.lwf.store(self.model)
        print("✅ Training Complete.\n")

    # --- Monitoring & Adaptive ---
    def scan_target(self, domain):
        print(f"\n🔍 [Phase 1] Active Scanning: {domain}"); print("-" * 60)
        results = self.scanner.scan(domain)
        if not results: print("✅ No configuration issues found.")
        for r in results: print(f"⚠️  {r['cat']}: {r['msg']}")
        print("-" * 60)

    def monitor_and_adapt(self, domain, traffic_stream):
        print(f"\n🛡️ [Phase 2] Live Monitoring for: {domain}")
        print("-" * 100)
        print(f"{'TIME':<12} {'REQUEST':<40} {'DETECTION':<25} {'STATUS':<10} {'ACTION'}")
        print("-" * 100)

        for req in traffic_stream:
            self.model.eval()
            ds = TrafficDataset([f"{domain}{req}"], [0], self.tokenizer, self.config.max_length)
            batch = ds[0]
            
            with torch.no_grad():
                logits = self.model(batch['input_ids'].unsqueeze(0).to(self.config.device),
                                    batch['log_features'].unsqueeze(0).to(self.config.device))
                probs = F.softmax(logits, dim=1)
                conf, pred = torch.max(probs, dim=1)
            
            lbl = OWASPLabelMapping.LABEL_TO_OWASP.get(pred.item(), "Unknown")
            status = "🟢 OK" if pred.item() == 0 else "🔴 ALERT"
            snippet = req[:40]
            
            action = "None"
            if pred.item() != 0:
                action = "🔄 Adapting..."
                self._adaptive_update(batch, pred.item())
            
            print(f"{time.strftime('%H:%M:%S'):<12} {snippet:<40} {lbl:<25} {status:<10} {action}")
        print("-" * 100)

    def _adaptive_update(self, batch, new_label):
        self.model.train()
        self.replay_buffer.add({'input_ids': batch['input_ids'], 'log_features': batch['log_features'], 'labels': torch.tensor(new_label)})
        history = self.replay_buffer.sample(4)
        inputs = [batch['input_ids']]; feats = [batch['log_features']]; lbls = [torch.tensor(new_label)]
        for h in history: inputs.append(h['input_ids']); feats.append(h['log_features']); lbls.append(h['labels'])
        inputs = torch.stack(inputs).to(self.config.device)
        feats = torch.stack(feats).to(self.config.device)
        lbls = torch.stack(lbls).to(self.config.device)
        self.optimizer.zero_grad()
        outputs = self.model(inputs, feats)
        loss = self.criterion(outputs, lbls)
        loss += self.ewc.penalty(self.config.ewc_lambda)
        loss += self.lwf.loss(self.model, inputs, feats, self.config.lwf_lambda)
        loss.backward()
        self.optimizer.step()
        self.lwf.store(self.model)
        self.model.eval()

# --- MAIN EXECUTION ---

def main():
    system = OWASPSystem(Config())
    
    # Paths Configuration
    paths = {
        'csic': "/home/miki/Downloads/csic_database.csv",
        'cic': "/home/miki/Downloads/MachineLearningCVE.csv",
        'payloads_folder': "/home/miki/Downloads/PayloadsAllTheThings-master"
    }
    
    # 1. Load and Train
    texts, labels = system.load_data(paths)
    system.train_initial(texts, labels)
    
    # 2. Interactive User Input
    print("\n" + "="*60)
    print("     TARGET SETUP")
    print("="*60)
    target_domain = input("👉 Please enter the target domain to scan (e.g., bdu.edu.et): ").strip()
    
    # Basic validation
    if not target_domain:
        print("No domain entered. Exiting.")
        return

    # 3. Scan Target
    system.scan_target(target_domain)
    
    # 4. Simulate Traffic (In real scenario, this would be a log stream)
    traffic = [
        "/index.html",
        "/admin/login.php",
        "/search?password=secret",
        "/item?id=1 UNION SELECT",
        "/proxy?url=http://internal",
        "/debug?trace=true"
    ]
    system.monitor_and_adapt(target_domain, traffic)

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
    
