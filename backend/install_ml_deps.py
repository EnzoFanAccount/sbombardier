"""
Helper script to install compatible PyTorch and DGL versions for SBOMbardier.
This handles the specific requirements for Windows environments.
"""
import os
import platform
import subprocess
import sys

def install_ml_dependencies():
    """Install PyTorch and DGL with appropriate versions for the current platform."""
    system = platform.system().lower()
    
    print(f"Installing ML dependencies for {system}...")
    
    # Uninstall existing packages first to avoid conflicts
    packages_to_remove = ["torch", "torchvision", "torchaudio", "dgl"]
    for package in packages_to_remove:
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", package])
    
    if system == "windows":
        # For Windows, use CPU-only versions for simplicity
        print("Installing PyTorch 2.0.1 (CPU version)")
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "torch==2.0.1", "torchvision==0.15.2", "torchaudio==2.0.2", 
            "--index-url", "https://download.pytorch.org/whl/cpu"
        ])
        
        print("Installing DGL 1.1.2 (CPU version)")
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "dgl==1.1.2", "-f", "https://data.dgl.ai/wheels/repo.html"
        ])
    else:
        # For Linux/Mac, use standard packages without CUDA
        print("Installing PyTorch 2.0.1")
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "torch==2.0.1", "torchvision==0.15.2", "torchaudio==2.0.2"
        ])
        
        print("Installing DGL 1.1.2")
        subprocess.run([
            sys.executable, "-m", "pip", "install", "dgl==1.1.2"
        ])
    
    # Verify the installations
    try:
        import torch
        print(f"PyTorch installed successfully, version: {torch.__version__}")
        
        import dgl
        print(f"DGL installed successfully, version: {dgl.__version__}")
        
        print("\nInstallation successful!")
    except ImportError as e:
        print(f"ERROR: Installation verification failed - {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = install_ml_dependencies()
    if not success:
        sys.exit(1)