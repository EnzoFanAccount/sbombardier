"""
Training script for ML models.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import tempfile
import io
import ast
from PIL import Image, ImageFormatter, ImageOps, ImageEnhance
from pygments import highlight, guess_lexer

import dgl
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset
from tqdm import tqdm
from git import Repo

from ..data.collectors import (LicenseCollector, MaintainerCollector,
                           VulnerabilityCollector)
from ..models.risk_models import (DependencyGNN, HybridRiskPredictor,
                               LicenseRiskLLM, VulnerabilityIVulCNN)
from ..scanners.sbom_generator import SBOMGenerator
from ..predictors.risk_predictor import RiskPredictor

class LicenseDataset(Dataset):
    """Dataset for license risk training."""
    
    def __init__(self, texts: List[str], labels: List[int]):
        """Initialize dataset.
        
        Args:
            texts: List of license texts
            labels: List of labels (0: compatible, 1: incompatible)
        """
        self.texts = texts
        self.labels = labels
        
    def __len__(self) -> int:
        return len(self.texts)
        
    def __getitem__(self, idx: int) -> Tuple[str, int]:
        return self.texts[idx], self.labels[idx]

class DependencyDataset(Dataset):
    """Dataset for dependency graph training."""
    
    def __init__(self, graphs: List[dgl.DGLGraph], labels: List[float]):
        """Initialize dataset.
        
        Args:
            graphs: List of dependency graphs
            labels: List of risk scores
        """
        self.graphs = graphs
        self.labels = labels
        
    def __len__(self) -> int:
        return len(self.graphs)
        
    def __getitem__(self, idx: int) -> Tuple[dgl.DGLGraph, float]:
        return self.graphs[idx], self.labels[idx]

class CodeToImageConverter:
    """Convert source code to normalized grayscale images with syntax highlighting."""
    
    def __init__(self, img_size: Tuple[int, int] = (64, 64)):
        self.img_size = img_size
        self.formatter = ImageFormatter(
            font_name="DejaVu Sans Mono",
            font_size=10,
            line_pad=2,
            style="monokai",
            line_numbers=False
        )
        
    def code_to_ast(self, code: str) -> Image.Image:
        """Generate AST visualization using graphviz."""
        tree = ast.parse(code)
        dot = Digraph()
        
        def add_node(node, parent=None):
            name = str(id(node))
            label = type(node).__name__
            dot.node(name, label)
            if parent:
                dot.edge(parent, name)
            for child in ast.iter_child_nodes(node):
                add_node(child, parent=name)
                
        add_node(tree)
        dot.format = 'png'
        png_bytes = dot.pipe()
        return Image.open(io.BytesIO(png_bytes)).convert('L')
    
    def code_to_image(self, code: str) -> torch.Tensor:
        """Convert code to normalized grayscale image tensor."""
        try:
            # Syntax highlighted image
            lexer = guess_lexer(code)
            highlighted = highlight(code, lexer, self.formatter)
            img = Image.open(io.BytesIO(highlighted)).convert('L')
        except:
            # Fallback to AST visualization
            img = self.code_to_ast(code)
            
        # Preprocessing pipeline
        img = ImageOps.fit(img, self.img_size)
        img = ImageOps.autocontrast(img)
        img = ImageEnhance.Sharpness(img).enhance(2.0)
        
        # Convert to tensor
        tensor = torch.tensor(np.array(img), dtype=torch.float32) / 255.0
        return tensor.unsqueeze(0)  # Add channel dimension

class CodeImageDataset(Dataset):
    """Dataset for vulnerability detection training."""
    
    def __init__(self, code_samples: List[str], labels: List[float]):
        self.converter = CodeToImageConverter()
        self.images = [self.converter.code_to_image(code) for code in code_samples]
        self.labels = torch.tensor(labels, dtype=torch.float32)
        
    def __len__(self) -> int:
        return len(self.images)
        
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        return self.images[idx], self.labels[idx]

def collect_training_data() -> Tuple[Dict, Dict, Dict]:
    """Collect training data from various sources.
    
    Returns:
        Tuple[Dict, Dict, Dict]: License, dependency, and vulnerability data
    """
    # Initialize collectors
    license_collector = LicenseCollector()
    vuln_collector = VulnerabilityCollector()
    maintainer_collector = MaintainerCollector()
    
    # Collect license data
    licenses = license_collector.collect_spdx_licenses()
    compatibility = license_collector.collect_license_compatibility()
    
    # Create license training pairs
    license_data = {
        "texts": [],
        "labels": []
    }
    
    for license_id, license in licenses.items():
        compatible = compatibility.get(license_id, [])
        for other_id, other in licenses.items():
            if other_id != license_id:
                license_data["texts"].append(f"{license['text']} [SEP] {other['text']}")
                license_data["labels"].append(1 if other_id in compatible else 0)
                
    # Collect vulnerability data
    nvd_vulns = vuln_collector.collect_nvd_data()
    osv_vulns = vuln_collector.collect_osv_data()
    
    vuln_data = {
        "descriptions": [],
        "severity": []
    }
    
    for vuln in nvd_vulns + osv_vulns:
        if vuln.get("description"):
            vuln_data["descriptions"].append(vuln["description"])
            vuln_data["severity"].append(vuln.get("severity", 0))
            
    # Real dependency graph collection
    dep_data = {
        "graphs": [],
        "labels": []
    }

    # Scan real open source projects from curated list
    project_urls = [
        "https://github.com/python/cpython",
        "https://github.com/django/django",
        "https://github.com/pallets/flask",
        "https://github.com/pypa/pip",
        "https://github.com/pandas-dev/pandas"
    ]

    for url in project_urls:
        try:
            # Clone repo to temp directory
            with tempfile.TemporaryDirectory() as tmpdir:
                repo_dir = Path(tmpdir) / "repo"
                Repo.clone_from(url, repo_dir)
                
                # Generate SBOM with dependency relationships
                generator = SBOMGenerator(repo_dir)
                generator.scan_dependencies()
                
                # Build graph from SBOM components
                g = dgl.DGLGraph()
                node_ids = {}
                
                # Add nodes with features
                for idx, component in enumerate(generator.components):
                    node_ids[component.name] = idx
                    g.add_nodes(1, data={
                        'feat': torch.tensor([
                            len(component.vulnerabilities),
                            1 if component.license_id else 0,
                            component.maintainer_score
                        ], dtype=torch.float)
                    })
                
                # Add edges based on dependencies
                for component in generator.components:
                    if component.dependencies:
                        for dep in component.dependencies:
                            if dep in node_ids:
                                g.add_edge(node_ids[component.name], node_ids[dep])

                # Calculate risk score (using existing predictor)
                predictor = RiskPredictor()
                risk_score = predictor.predict_sbom_risk(generator.components)
                
                dep_data["graphs"].append(g)
                dep_data["labels"].append(risk_score)

        except Exception as e:
            print(f"Error processing {url}: {str(e)}")
            continue

    # Fallback to synthetic data if no real graphs collected
    if not dep_data["graphs"]:
        print("Warning: Using synthetic dependency data")
        # This is a placeholder that creates synthetic graphs
        for _ in range(1000):  # Create 1000 synthetic graphs
            num_nodes = np.random.randint(5, 20)
            src = torch.randint(0, num_nodes, (num_nodes * 2,))
            dst = torch.randint(0, num_nodes, (num_nodes * 2,))
            g = dgl.graph((src, dst))
            g.ndata["feat"] = torch.randn(num_nodes, 64)
            
            # Synthetic risk score based on graph properties
            risk = min(1.0, g.number_of_edges() / (num_nodes * num_nodes))
            
            dep_data["graphs"].append(g)
            dep_data["labels"].append(risk)
        
    return license_data, dep_data, vuln_data

def train_license_model(data: Dict, 
                      model: Optional[LicenseRiskLLM] = None,
                      num_epochs: int = 10,
                      batch_size: int = 32,
                      learning_rate: float = 1e-4) -> LicenseRiskLLM:
    """Train license risk model.
    
    Args:
        data: Training data
        model: Optional pre-trained model
        num_epochs: Number of training epochs
        batch_size: Training batch size
        learning_rate: Learning rate
        
    Returns:
        LicenseRiskLLM: Trained model
    """
    # Create or load model
    if model is None:
        model = LicenseRiskLLM()
        
    # Prepare data
    texts = data["texts"]
    labels = torch.tensor(data["labels"])
    
    # Split data
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.2
    )
    
    # Create datasets
    train_dataset = LicenseDataset(train_texts, train_labels)
    val_dataset = LicenseDataset(val_texts, val_labels)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)
    
    # Training setup
    optimizer = optim.AdamW(model.parameters(), lr=learning_rate)
    criterion = nn.BCEWithLogitsLoss()
    
    # Training loop
    best_val_loss = float("inf")
    for epoch in range(num_epochs):
        model.train()
        train_loss = 0
        
        for batch_texts, batch_labels in tqdm(train_loader):
            optimizer.zero_grad()
            
            # Forward pass
            inputs = model.tokenizer(
                batch_texts,
                padding=True,
                truncation=True,
                return_tensors="pt"
            )
            outputs = model(**inputs)
            loss = criterion(outputs.logits.squeeze(), batch_labels.float())
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            
        # Validation
        model.eval()
        val_loss = 0
        
        with torch.no_grad():
            for batch_texts, batch_labels in val_loader:
                inputs = model.tokenizer(
                    batch_texts,
                    padding=True,
                    truncation=True,
                    return_tensors="pt"
                )
                outputs = model(**inputs)
                loss = criterion(outputs.logits.squeeze(), batch_labels.float())
                val_loss += loss.item()
                
        # Save best model
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            model_path = Path("models") / f"license_model_{datetime.now():%Y%m%d_%H%M%S}"
            model.save_pretrained(model_path)
            
        print(f"Epoch {epoch+1}/{num_epochs}")
        print(f"Train Loss: {train_loss/len(train_loader):.4f}")
        print(f"Val Loss: {val_loss/len(val_loader):.4f}")
        
    return model

def train_dependency_model(data: Dict,
                        model: Optional[DependencyGNN] = None,
                        num_epochs: int = 10,
                        batch_size: int = 32,
                        learning_rate: float = 1e-4) -> DependencyGNN:
    """Train dependency graph model.
    
    Args:
        data: Training data
        model: Optional pre-trained model
        num_epochs: Number of training epochs
        batch_size: Training batch size
        learning_rate: Learning rate
        
    Returns:
        DependencyGNN: Trained model
    """
    # Create or load model
    if model is None:
        model = DependencyGNN(in_feats=64)  # Match feature size from data collection
        
    # Prepare data
    graphs = data["graphs"]
    labels = torch.tensor(data["labels"])
    
    # Split data
    train_graphs, val_graphs, train_labels, val_labels = train_test_split(
        graphs, labels, test_size=0.2
    )
    
    # Create datasets
    train_dataset = DependencyDataset(train_graphs, train_labels)
    val_dataset = DependencyDataset(val_graphs, val_labels)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)
    
    # Training setup
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()
    
    # Training loop
    best_val_loss = float("inf")
    for epoch in range(num_epochs):
        model.train()
        train_loss = 0
        
        for batch_graphs, batch_labels in tqdm(train_loader):
            optimizer.zero_grad()
            
            # Forward pass
            predictions = model(batch_graphs, batch_graphs[0].ndata["feat"])
            loss = criterion(predictions.squeeze(), batch_labels)
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            
        # Validation
        model.eval()
        val_loss = 0
        
        with torch.no_grad():
            for batch_graphs, batch_labels in val_loader:
                predictions = model(batch_graphs, batch_graphs[0].ndata["feat"])
                loss = criterion(predictions.squeeze(), batch_labels)
                val_loss += loss.item()
                
        # Save best model
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), f"models/dependency_model_{datetime.now():%Y%m%d_%H%M%S}.pt")
            
        print(f"Epoch {epoch+1}/{num_epochs}")
        print(f"Train Loss: {train_loss/len(train_loader):.4f}")
        print(f"Val Loss: {val_loss/len(val_loader):.4f}")
        
    return model

def train_vulnerability_model(data: Dict,
                           model: Optional[VulnerabilityIVulCNN] = None,
                           num_epochs: int = 10,
                           batch_size: int = 32,
                           learning_rate: float = 1e-4) -> VulnerabilityIVulCNN:
    """Train vulnerability detection model.
    
    Args:
        data: Training data
        model: Optional pre-trained model
        num_epochs: Number of training epochs
        batch_size: Training batch size
        learning_rate: Learning rate
        
    Returns:
        VulnerabilityIVulCNN: Trained model
    """
    # Create or load model
    if model is None:
        model = VulnerabilityIVulCNN()
        
    # Updated data preparation
    code_samples = data["descriptions"]  # List of vulnerable code snippets
    severity = data["severity"]  # Normalized severity scores
    
    # Split data
    train_code, val_code, train_labels, val_labels = train_test_split(
        code_samples, severity, test_size=0.2
    )
    
    # Create datasets
    train_dataset = CodeImageDataset(train_code, train_labels)
    val_dataset = CodeImageDataset(val_code, val_labels)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)
    
    # Training setup
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()
    
    # Training loop
    best_val_loss = float("inf")
    for epoch in range(num_epochs):
        model.train()
        train_loss = 0
        
        for batch_images, batch_labels in tqdm(train_loader):
            optimizer.zero_grad()
            
            # Forward pass
            predictions = model(batch_images)
            loss = criterion(predictions.squeeze(), batch_labels)
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            
        # Validation
        model.eval()
        val_loss = 0
        
        with torch.no_grad():
            for batch_images, batch_labels in val_loader:
                predictions = model(batch_images)
                loss = criterion(predictions.squeeze(), batch_labels)
                val_loss += loss.item()
                
        # Save best model
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), f"models/vulnerability_model_{datetime.now():%Y%m%d_%H%M%S}.pt")
            
        print(f"Epoch {epoch+1}/{num_epochs}")
        print(f"Train Loss: {train_loss/len(train_loader):.4f}")
        print(f"Val Loss: {val_loss/len(val_loader):.4f}")
        
    return model

def train_all_models():
    """Train all ML models."""
    print("Collecting training data...")
    license_data, dep_data, vuln_data = collect_training_data()
    
    print("\nTraining license risk model...")
    license_model = train_license_model(license_data)
    
    print("\nTraining dependency graph model...")
    dependency_model = train_dependency_model(dep_data)
    
    print("\nTraining vulnerability detection model...")
    vulnerability_model = train_vulnerability_model(vuln_data)
    
    # Create and save hybrid model
    hybrid_model = HybridRiskPredictor()
    hybrid_model.llm = license_model
    hybrid_model.gnn = dependency_model
    hybrid_model.cnn = vulnerability_model
    
    # Save model configuration
    config = {
        "license_model": str(Path("models").glob("license_model_*.pt")),
        "dependency_model": str(Path("models").glob("dependency_model_*.pt")),
        "vulnerability_model": str(Path("models").glob("vulnerability_model_*.pt"))
    }
    
    with open("models/hybrid_model_config.json", "w") as f:
        json.dump(config, f, indent=2)
        
    print("\nTraining complete. Models saved in 'models' directory.")

if __name__ == "__main__":
    train_all_models() 