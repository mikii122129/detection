#!/usr/bin/env python3
"""
OWASP Top 10 Detection System - Persistence Focused
=====================================================
1. Trains model if 'owasp_trained_model.pth' does not exist.
2. Saves model after training.
3. Loads model instantly on subsequent runs (No retraining).
"""

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


class FallbackTokenizer:
    """Small offline tokenizer used when Hugging Face assets are unavailable."""

    def __init__(self, vocab_size: int = 30522):
        self.vocab_size = vocab_size

    def __call__(self, text, truncation=True, padding='max_length', max_length=128, return_tensors='pt'):
        tokens = (text or "").lower().split()
        ids = [101]
        for token in tokens:
            ids.append(abs(hash(token)) % (self.vocab_size - 1000) + 1000)
        ids.append(102)
        ids = ids[:max_length]
        if len(ids) < max_length:
            ids.extend([0] * (max_length - len(ids)))
        tensor = torch.tensor([ids], dtype=torch.long)
        return {'input_ids': tensor}

@dataclass
class OWASPLabelMapping:
    LABEL_TO_OWASP = {
        0: 'Benign',
        1: 'A01-BrokenAccessControl',
        2: 'A02-CryptographicFailures',
        3: 'A03-Injection',
        4: 'A04-InsecureDesign',
        5: 'A05-SecurityMisconfiguration',
        6: 'A06-VulnerableOutdatedComponents',
        7: 'A07-IdentificationAuthFailures',
        8: 'A08-SoftwareDataIntegrityFailures',
        9: 'A09-SecurityLoggingMonitoringFailures',
        10: 'A10-ServerSideRequestForgery'
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
    epochs: int = 7
    lr: float = 1e-3
    device: str = "cpu"
    replay_buffer_size: int = 2000
    ewc_lambda: float = 0.5
    lwf_lambda: float = 1.0

# --- 1. Feature Engineering ---

def calculate_entropy(string):
    if not string: return 0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def extract_url_features(url: str) -> np.ndarray:
    if not url: return np.zeros(32, dtype=np.float32)
    features = []
    text = url.lower()
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('/'))
    features.append(url.count('='))
    features.append(url.count('?'))
    features.append(calculate_entropy(text))
    features.append(1 if re.search(r'(union|select|script|alert|onerror)', text) else 0)
    features.append(1 if re.search(r'(admin|login|dashboard|config|token)', text) else 0)
    features.append(1 if re.search(r'(http:|https:|ftp:|localhost|\:\d+)', text) else 0)
    features.append(1 if re.search(r'(id=\d+|object|serialize|file=)', text) else 0)
    features.append(1 if re.search(r'(password|credit_card|ssn|secret)', text) else 0)
    while len(features) < 32: features.append(0)
    return np.array(features[:32], dtype=np.float32)

# --- 2. Dataset & Model ---

class TrafficDataset(Dataset):
    def __init__(self, requests_list: List[str], labels: List[int], tokenizer, max_length=128):
        self.requests = requests_list; self.labels = labels; self.tokenizer = tokenizer; self.max_length = max_length
    def __len__(self): return len(self.labels)
    def __getitem__(self, idx):
        text = str(self.requests[idx])
        features = extract_url_features(text)
        encoded = self.tokenizer(text, truncation=True, padding='max_length', max_length=self.max_length, return_tensors='pt')
        return {'input_ids': encoded['input_ids'].squeeze(0), 'log_features': torch.tensor(features, dtype=torch.float), 'labels': torch.tensor(self.labels[idx], dtype=torch.long)}

class BiLSTMModel(nn.Module):
    def __init__(self, config: Config):
        super().__init__()
        self.embedding = nn.Embedding(config.vocab_size, config.embedding_dim)
        self.lstm = nn.LSTM(config.embedding_dim, config.hidden_dim, num_layers=config.num_layers, bidirectional=config.bidirectional, batch_first=True, dropout=0.3)
        self.attention = nn.Linear(config.hidden_dim * 2, 1)
        self.log_projector = nn.Sequential(nn.Linear(32, config.hidden_dim), nn.ReLU(), nn.Dropout(0.3))
        lstm_output_dim = config.hidden_dim * 2
        self.classifier = nn.Sequential(nn.Linear(lstm_output_dim + config.hidden_dim, config.hidden_dim), nn.ReLU(), nn.Dropout(0.3), nn.Linear(config.hidden_dim, config.num_labels))

    def forward(self, input_ids, log_features):
        embeds = self.embedding(input_ids)
        lstm_out, _ = self.lstm(embeds)
        attn_weights = F.softmax(self.attention(lstm_out), dim=1)
        context = torch.sum(attn_weights * lstm_out, dim=1)
        log_proj = self.log_projector(log_features)
        fused = torch.cat([context, log_proj], dim=1)
        return self.classifier(fused)

# --- 3. Adaptive Components ---

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
        logger.info("Computing Fisher Information (EWC)..."); self.model.eval()
        self.fisher = {n: torch.zeros_like(p, device=self.device) for n, p in self.model.named_parameters() if p.requires_grad}
        for batch in loader:
            self.model.zero_grad(); out = self.model(batch['input_ids'].to(self.device), batch['log_features'].to(self.device))
            loss = criterion(out, batch['labels'].to(self.device)); loss.backward()
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
            if not url.startswith("https"): findings.append({'cat': 'A02', 'msg': 'No HTTPS'})
            if 'Strict-Transport-Security' not in headers: findings.append({'cat': 'A02', 'msg': 'Missing HSTS'})
            for h in ['X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options']:
                if h not in headers: findings.append({'cat': 'A05', 'msg': f'Missing {h}'})
            server = headers.get('Server', '')
            if re.search(r'\d', server): findings.append({'cat': 'A06', 'msg': f'Version Exposed: {server}'})
        except Exception as e: findings.append({'cat': 'A09', 'msg': f'Connection Failed: {e}'})
        return findings

# --- 5. Main System ---

class OWASPSystem:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.model = BiLSTMModel(self.config).to(self.config.device)
        self.tokenizer = self._build_tokenizer()
        self.scanner = WebsiteScanner()
        self.replay_buffer = ReplayBuffer(self.config.replay_buffer_size)
        self.ewc = EWC(self.model, self.config.device)
        self.lwf = LwF()
        self.optimizer = AdamW(self.model.parameters(), lr=self.config.lr)
        self.scheduler = ReduceLROnPlateau(self.optimizer, mode='max', factor=0.5, patience=1)
        self.criterion = nn.CrossEntropyLoss()

    def _build_tokenizer(self):
        try:
            return AutoTokenizer.from_pretrained("distilbert-base-uncased", local_files_only=True)
        except Exception as exc:
            logger.warning("Falling back to offline tokenizer: %s", exc)
            return FallbackTokenizer(self.config.vocab_size)
        
    # --- SAVE & LOAD FUNCTIONS ---
    def save_checkpoint(self, path="owasp_trained_model.pth"):
        logger.info(f"Saving model checkpoint to {path}...")
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'ewc_fisher': self.ewc.fisher,
            'ewc_optimal': self.ewc.optimal,
            'ewc_initialized': self.ewc.initialized,
            'lwf_old_state': self.lwf.old_state,
            'replay_buffer': list(self.replay_buffer.buffer)
        }
        torch.save(checkpoint, path)
        logger.info("✅ Model saved successfully.")

    def load_checkpoint(self, path="owasp_trained_model.pth"):
        if not os.path.exists(path):
            return False
        
        logger.info(f"Found saved model at {path}. Loading...")
        try:
            checkpoint = torch.load(path, map_location=self.config.device)
            
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            
            # Restore EWC
            self.ewc.fisher = checkpoint.get('ewc_fisher', {})
            self.ewc.optimal = checkpoint.get('ewc_optimal', {})
            self.ewc.initialized = checkpoint.get('ewc_initialized', False)
            
            # Restore LwF
            self.lwf.old_state = checkpoint.get('lwf_old_state', None)
            
            # Restore Replay Buffer
            buffer_list = checkpoint.get('replay_buffer', [])
            self.replay_buffer.buffer = deque(buffer_list, maxlen=self.config.replay_buffer_size)
            
            logger.info("✅ Model loaded successfully. Skipping training.")
            return True
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}. Retraining...")
            return False

    def predict_request(self, domain: str, request_path: str) -> Dict:
        request_text = self._build_request_text(domain, request_path)
        self.model.eval()
        dataset = TrafficDataset([request_text], [0], self.tokenizer, self.config.max_length)
        batch = dataset[0]

        with torch.no_grad():
            logits = self.model(
                batch['input_ids'].unsqueeze(0).to(self.config.device),
                batch['log_features'].unsqueeze(0).to(self.config.device)
            )
            probs = F.softmax(logits, dim=1)
            confidence, pred = torch.max(probs, dim=1)

        label_id = pred.item()
        return {
            "request_text": request_text,
            "label_id": label_id,
            "label": OWASPLabelMapping.LABEL_TO_OWASP.get(label_id, "Unknown"),
            "confidence": round(confidence.item() * 100, 1),
            "is_malicious": label_id != 0,
        }

    def _build_request_text(self, domain: str, request_path: str) -> str:
        clean_domain = (domain or "").rstrip("/")
        clean_path = request_path or "/"
        if clean_path.startswith("http://") or clean_path.startswith("https://"):
            return clean_path
        if not clean_path.startswith("/"):
            clean_path = f"/{clean_path}"
        return f"{clean_domain}{clean_path}"

    # --- DATA LOADING ---
    def load_data(self, paths: Dict[str, str]):
        texts, labels = [], []
        # 1. CSIC
        try:
            logger.info(f"Loading CSIC: {paths['csic']}"); df = pd.read_csv(paths['csic'])
            url_col = next((c for c in df.columns if 'url' in c.lower() or 'path' in c.lower()), None)
            label_col = next((c for c in df.columns if 'label' in c.lower() or 'class' in c.lower()), None)
            if url_col and label_col:
                for _, r in df.iterrows(): texts.append(str(r[url_col])); labels.append(self._map_label(r[label_col]))
        except: pass
        # 2. CIC-IDS2017
        try:
            logger.info(f"Loading CIC-IDS2017: {paths['cic']}"); df_cic = pd.read_csv(paths['cic']); df_cic.columns = [c.strip() for c in df_cic.columns]
            users = ['admin', 'root', 'test', 'user1', 'manager']; paths_login = ['/login', '/signin', '/auth', '/admin/login']
            for _, r in df_cic.iterrows():
                lbl = str(r['Label']).lower()
                if 'brute force' in lbl: texts.append(f"POST {random.choice(paths_login)}?user={random.choice(users)}&pass=pass123 HTTP/1.1"); labels.append(7)
                elif 'sql injection' in lbl: texts.append("GET /item?id=1' OR '1'='1"); labels.append(3)
                elif 'xss' in lbl: texts.append("GET /search?q=<script>alert(1)</script>"); labels.append(3)
                elif 'benign' in lbl and np.random.rand() > 0.98: texts.append("GET /index.html"); labels.append(0)
        except: pass
        # 3. PayloadsAllTheThings
        try:
            logger.info(f"Scanning Payloads: {paths['payloads_folder']}")
            folder_map = {'SQL Injection': 3, 'XSS': 3, 'SSRF': 10, 'Local File Inclusion': 4, 'CSRF': 1}
            for folder_name, label_id in folder_map.items():
                target_folder = os.path.join(paths['payloads_folder'], folder_name)
                if os.path.exists(target_folder):
                    files = glob.glob(os.path.join(target_folder, '**', '*.txt'), recursive=True)
                    for f in files:
                        try:
                            with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                                for line in file:
                                    if len(line) > 5: texts.append(f"GET /search?q={line.strip()}"); labels.append(label_id)
                        except: continue
        except: pass
        # 4. Synthetic Fill
        webgoat_synth = [("GET /WebGoat/Crypto?enc=weak", 2), ("POST /WebGoat/Deserialize", 8)]
        for t, l in webgoat_synth: texts.extend([t] * 50); labels.extend([l] * 50)
        synth = [("GET /admin HTTP/1.1", 1), ("GET /.env HTTP/1.1", 5), ("GET /cgi-bin/test-cgi", 6), ("POST /login", 7), ("GET /debug", 9), ("GET /proxy?url=http://...", 10), ("GET /index.html", 0)]
        for t, l in synth: texts.extend([t] * 200); labels.extend([l] * 200)
        logger.info(f"Total samples: {len(texts)}")
        return texts, labels

    def _map_label(self, raw):
        r = str(raw).lower()
        if r in ['normal', 'benign', '0', 'valid']: return 0
        if r in ['sql injection', 'sqli', 'xss']: return 3
        return 3

    # --- TRAINING ---
    def train_initial(self, texts, labels):
        unique_classes = np.unique(labels); weights = compute_class_weight('balanced', classes=unique_classes, y=labels)
        class_w = np.ones(self.config.num_labels)
        for i, c in enumerate(unique_classes): class_w[c] = weights[i]
        self.criterion = nn.CrossEntropyLoss(weight=torch.tensor(class_w, dtype=torch.float, device=self.config.device))

        train_t, test_t, train_l, test_l = train_test_split(texts, labels, test_size=0.2, random_state=42)
        train_ds = TrafficDataset(train_t, train_l, self.tokenizer, self.config.max_length)
        train_loader = DataLoader(train_ds, batch_size=self.config.batch_size, shuffle=True)
        
        logger.info("Starting Training...")
        for epoch in range(self.config.epochs):
            self.model.train(); total_loss = 0
            for batch in train_loader:
                self.optimizer.zero_grad()
                out = self.model(batch['input_ids'].to(self.config.device), batch['log_features'].to(self.config.device))
                loss = self.criterion(out, batch['labels'].to(self.config.device))
                loss.backward(); self.optimizer.step(); total_loss += loss.item()
            
            self.model.eval(); preds, true = [], []
            with torch.no_grad():
                for b in train_loader:
                    out = self.model(b['input_ids'].to(self.config.device), b['log_features'].to(self.config.device))
                    preds.extend(torch.argmax(out, dim=1).cpu().numpy()); true.extend(b['labels'].numpy())
            acc = accuracy_score(true, preds)
            self.scheduler.step(acc)
            logger.info(f"Epoch {epoch+1}/{self.config.epochs} | Loss: {total_loss/len(train_loader):.4f} | Acc: {acc*100:.2f}%")

        print("\n" + "="*60); print("     FINAL MODEL EVALUATION"); print("="*60)
        test_ds = TrafficDataset(test_t, test_l, self.tokenizer, self.config.max_length); test_loader = DataLoader(test_ds, batch_size=self.config.batch_size)
        self.model.eval(); preds, true = [], []
        with torch.no_grad():
            for b in test_loader:
                out = self.model(b['input_ids'].to(self.config.device), b['log_features'].to(self.config.device))
                preds.extend(torch.argmax(out, dim=1).cpu().numpy()); true.extend(b['labels'].numpy())
        print(f"Final Test Accuracy: {accuracy_score(true, preds)*100:.2f}%")
        print(classification_report(true, preds, labels=list(range(11)), target_names=list(OWASPLabelMapping.LABEL_TO_OWASP.values()), zero_division=0))
        
        self.ewc.compute_fisher(train_loader, self.criterion)
        self.lwf.store(self.model)
        print("✅ Training Complete.\n")

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
                logits = self.model(batch['input_ids'].unsqueeze(0).to(self.config.device), batch['log_features'].unsqueeze(0).to(self.config.device))
                probs = F.softmax(logits, dim=1); conf, pred = torch.max(probs, dim=1)
            
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
        inputs = torch.stack(inputs).to(self.config.device); feats = torch.stack(feats).to(self.config.device); lbls = torch.stack(lbls).to(self.config.device)
        self.optimizer.zero_grad()
        outputs = self.model(inputs, feats)
        loss = self.criterion(outputs, lbls)
        loss += self.ewc.penalty(self.config.ewc_lambda)
        loss += self.lwf.loss(self.model, inputs, feats, self.config.lwf_lambda)
        loss.backward(); self.optimizer.step()
        self.lwf.store(self.model); self.model.eval()

# --- MAIN EXECUTION ---

def main():
    # Initialize System
    system = OWASPSystem(Config())
    
    # Define checkpoint filename
    checkpoint_file = "owasp_trained_model.pth"
    
    # TRY TO LOAD EXISTING MODEL
    if system.load_checkpoint(checkpoint_file):
        print("🚀 Using pre-trained model.")
    else:
        # IF NO MODEL FOUND, TRAIN FROM SCRATCH
        print("🚫 No saved model found. Starting training process...")
        paths = {
            'csic': "/home/miki/Downloads/csic_database.csv",
            'cic': "/home/miki/Downloads/MachineLearningCVE.csv",
            'payloads_folder': "/home/miki/Downloads/PayloadsAllTheThings-master"
        }
        texts, labels = system.load_data(paths)
        system.train_initial(texts, labels)
        
        # SAVE THE MODEL FOR NEXT TIME
        system.save_checkpoint(checkpoint_file)

    # Target Setup
    print("\n" + "="*60)
    print("     TARGET SETUP")
    print("="*60)
    target_domain = input("👉 Please enter the target domain to scan (e.g., bdu.edu.et): ").strip()
    
    if not target_domain:
        print("No domain entered. Exiting.")
        return

    # Run Phases
    system.scan_target(target_domain)
    
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
