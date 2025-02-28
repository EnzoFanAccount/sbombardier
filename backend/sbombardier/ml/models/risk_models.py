"""
ML models for risk prediction, including LLM, GNN, and CNN-based models.
"""
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

# Check PyTorch version before importing DGL
try:
    import torch
    torch_version = torch.__version__
    major, minor = map(int, torch_version.split(".")[:2])
    
    # Only attempt to import DGL if PyTorch version is compatible
    try:
        import dgl
        DGL_AVAILABLE = True
    except ImportError as e:
        dgl = None
        DGL_AVAILABLE = False
        print(f"WARNING: DGL import failed in risk_models.py: {e}")
        print("Graph neural network features will be disabled.")
        print("To enable full functionality, ensure PyTorch and DGL versions are compatible.")
    except FileNotFoundError as e:
        dgl = None
        DGL_AVAILABLE = False
        print(f"WARNING: DGL library files not found in risk_models.py: {e}")
        print(f"Current PyTorch version: {torch_version}")
        print("Graph neural network features will be disabled.")
        print("To enable full functionality, install compatible DGL version for your PyTorch.")
except ImportError:
    torch = None
    dgl = None
    DGL_AVAILABLE = False
    print("WARNING: PyTorch not found. Graph neural network features will be disabled.")

import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                       DistilBertForSequenceClassification, DistilBertTokenizer)

class ModelType(str, Enum):
    """Supported model types."""
    LLM = "llm"
    GNN = "gnn"
    CNN = "cnn"
    HYBRID = "hybrid"

@dataclass
class RiskPrediction:
    """Risk prediction result."""
    risk_score: float
    confidence: float
    risk_factors: List[str]
    suggested_remediation: Optional[str] = None

class LicenseRiskLLM(nn.Module):
    """Fine-tuned DistilBERT model for license risk prediction."""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize license risk LLM.
        
        Args:
            model_path: Path to pre-trained model
        """
        super().__init__()
        
        if model_path and Path(model_path).exists():
            self.model = DistilBertForSequenceClassification.from_pretrained(model_path)
            self.tokenizer = DistilBertTokenizer.from_pretrained(model_path)
        else:
            # Use base DistilBERT model
            self.model = DistilBertForSequenceClassification.from_pretrained(
                "distilbert-base-uncased",
                num_labels=2  # Compatible/Incompatible
            )
            self.tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
            
    def forward(self, license_text: str) -> RiskPrediction:
        """Predict license compatibility risk.
        
        Args:
            license_text: License text to analyze
            
        Returns:
            RiskPrediction: Risk prediction result
        """
        inputs = self.tokenizer(
            license_text,
            return_tensors="pt",
            truncation=True,
            max_length=512
        )
        
        outputs = self.model(**inputs)
        probabilities = F.softmax(outputs.logits, dim=1)
        
        risk_score = probabilities[0][1].item()  # Probability of incompatibility
        confidence = max(probabilities[0]).item()
        
        # Extract risk factors from attention weights
        attention = outputs.attentions[-1].mean(dim=1)  # Use last layer
        tokens = self.tokenizer.convert_ids_to_tokens(inputs.input_ids[0])
        
        # Get top attended tokens as risk factors
        attention_weights = attention[0].mean(dim=0)
        top_k = 5
        top_indices = attention_weights.topk(top_k).indices
        risk_factors = [tokens[idx] for idx in top_indices]
        
        return RiskPrediction(
            risk_score=risk_score,
            confidence=confidence,
            risk_factors=risk_factors
        )

class DependencyGNN(nn.Module):
    """Graph Neural Network for analyzing dependency relationships."""
    
    def __init__(self, in_feats: int, hidden_size: int = 64):
        """Initialize dependency GNN.
        
        Args:
            in_feats: Number of input features
            hidden_size: Hidden layer size
        """
        super().__init__()

        if not DGL_AVAILABLE:
            raise ImportError(
                "DGL is required for DependencyGNN but not available. "
                "Ensure PyTorch and DGL versions are compatible."
            )
        
        self.layers = nn.ModuleList([
            dgl.nn.GraphConv(in_feats, hidden_size),
            dgl.nn.GraphConv(hidden_size, hidden_size),
            dgl.nn.GraphConv(hidden_size, 1)
        ])
        
        self.attention = dgl.nn.GATConv(
            hidden_size,
            hidden_size,
            num_heads=4
        )
        
    def forward(self, g: dgl.DGLGraph, features: torch.Tensor) -> RiskPrediction:
        """Analyze dependency graph for risks.
        
        Args:
            g: Dependency graph
            features: Node features
            
        Returns:
            RiskPrediction: Risk prediction result
        """
        h = features
        
        # Graph convolution layers
        for i, layer in enumerate(self.layers[:-1]):
            h = layer(g, h)
            h = F.relu(h)
            
        # Attention layer
        h, attention_weights = self.attention(g, h)
        h = h.mean(dim=1)  # Average attention heads
        
        # Final prediction layer
        risk_scores = torch.sigmoid(self.layers[-1](g, h))
        
        # Get high-risk nodes
        top_k = 5
        high_risk_indices = risk_scores.squeeze().topk(top_k).indices
        risk_factors = [f"Node {idx.item()}" for idx in high_risk_indices]
        
        return RiskPrediction(
            risk_score=risk_scores.mean().item(),
            confidence=attention_weights.mean().item(),
            risk_factors=risk_factors
        )

class VulnerabilityIVulCNN(nn.Module):
    """CNN-based model for vulnerability detection (IVul architecture)."""
    
    def __init__(self):
        """Initialize IVul CNN model."""
        super().__init__()
        
        self.conv_layers = nn.Sequential(
            nn.Conv2d(1, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2)
        )
        
        self.fc_layers = nn.Sequential(
            nn.Linear(128 * 8 * 8, 512),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(512, 1)
        )
        
    def forward(self, code_image: torch.Tensor) -> RiskPrediction:
        """Detect vulnerabilities in code.
        
        Args:
            code_image: Grayscale code image tensor
            
        Returns:
            RiskPrediction: Risk prediction result
        """
        # Ensure input is grayscale image
        if code_image.dim() == 3:
            code_image = code_image.unsqueeze(0)  # Add batch dimension
            
        features = self.conv_layers(code_image)
        features = features.view(features.size(0), -1)
        
        # Get raw logits before sigmoid
        logits = self.fc_layers(features)
        
        # Calculate risk score and confidence
        risk_score = torch.sigmoid(logits).item()
        
        # Confidence based on distance from decision boundary
        confidence = (1.0 - 2.0 * abs(risk_score - 0.5)).item()  # Ranges 0-1
        
        # Confidence calibration using temperature scaling
        # (Would require validation data to calibrate - placeholder example)
        temperature = 0.5  # Should be learned in practice
        calibrated_confidence = torch.sigmoid(logits / temperature).item()
        
        # Extract feature importance from conv layers
        activation_maps = []
        x = code_image
        for layer in self.conv_layers:
            x = layer(x)
            if isinstance(layer, nn.Conv2d):
                activation_maps.append(x.detach())
                
        # Get risk factors from high-activation regions
        if activation_maps:
            # Use last conv layer's activations for localization
            last_activation = activation_maps[-1].mean(dim=1)  # Average across channels
            top_k = 5
            _, top_indices = torch.topk(last_activation.flatten(), top_k)
            
            # Convert indices to spatial positions (H, W)
            grid_size = last_activation.shape[-1]
            risk_factors = []
            for idx in top_indices:
                h = idx // grid_size
                w = idx % grid_size
                risk_factors.append(f"High-activation region at ({h},{w})")
        else:
            risk_factors = ["No significant activation patterns detected"]
            
        return RiskPrediction(
            risk_score=risk_score,
            confidence=calibrated_confidence,  # Use calibrated confidence
            risk_factors=risk_factors
        )

class HybridRiskPredictor:
    """Hybrid model combining LLM, GNN, and CNN predictions."""
    
    def __init__(self):
        """Initialize hybrid risk predictor."""
        self.llm = LicenseRiskLLM()

        # Only initialize GNN if DGL is available
        if DGL_AVAILABLE:
            try:
                self.gnn = DependencyGNN(in_feats=64)  # Adjust feature size as needed
            except Exception as e:
                print(f"Warning: Could not initialize DependencyGNN: {e}")
                self.gnn = None
        else:
            self.gnn = None

        self.cnn = VulnerabilityIVulCNN()
        
    def predict(self,
               license_text: Optional[str] = None,
               dependency_graph: Optional[dgl.DGLGraph] = None,
               code_image: Optional[torch.Tensor] = None) -> RiskPrediction:
        """Generate combined risk prediction.
        
        Args:
            license_text: License text to analyze
            dependency_graph: Dependency graph with features
            code_image: Code as grayscale image
            
        Returns:
            RiskPrediction: Combined risk prediction
        """
        # Initialize predictors
        predictions = []
        risk_factors = []

        # Get LLM prediction for license
        if license_text:
            llm_pred = self.llm(license_text)
            predictions.append(llm_pred.risk_score)
            risk_factors.extend(llm_pred.risk_factors)
            
        if dependency_graph and self.gnn is not None and DGL_AVAILABLE:
            try:
                if isinstance(dependency_graph, dgl.DGLGraph):
                    features = torch.randn(dependency_graph.number_of_nodes(), 64)
                    gnn_pred = self.gnn(dependency_graph, features)
                    predictions.append(gnn_pred.risk_score)
                    risk_factors.extend(gnn_pred.risk_factors)
            except Exception as e:
                print(f"Warning: GNN prediction failed: {e}")
            
        if code_image is not None:
            cnn_pred = self.cnn(code_image)
            predictions.append(cnn_pred.risk_score)
            risk_factors.extend(cnn_pred.risk_factors)
            
        if not predictions:
            raise ValueError("No inputs provided for prediction")
            
        # Combine predictions
        weights = np.array([0.33, 0.33, 0.33])  # Equal weights for simplicity
        combined_score = sum(p * w for p, w in zip(predictions, weights))
        combined_confidence = sum(p.confidence * w for p, w in zip(predictions, weights))
        
        # Combine risk factors
        risk_factors = []
        for pred in predictions:
            risk_factors.extend(pred.risk_factors)
            
        return RiskPrediction(
            risk_score=combined_score,
            confidence=combined_confidence,
            risk_factors=risk_factors[:5]  # Top 5 factors
        ) 