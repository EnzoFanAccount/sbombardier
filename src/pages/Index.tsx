
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Upload, Shield, FileSearch, GitBranch } from "lucide-react";

const Index = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-neutral-50 to-neutral-100">
      <div className="container px-4 py-8 mx-auto max-w-7xl">
        <header className="text-center mb-16 animate-in">
          <Badge variant="outline" className="mb-4">
            Beta
          </Badge>
          <h1 className="text-4xl font-bold tracking-tight text-neutral-900 sm:text-6xl mb-4">
            SBOMbardier
          </h1>
          <p className="text-lg text-neutral-600 max-w-2xl mx-auto">
            AI-powered SBOM validation and security analysis for your dependencies
          </p>
        </header>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 mb-12">
          <Card className="metric-card">
            <Shield className="w-8 h-8 mb-4 text-success-DEFAULT" />
            <h3 className="text-lg font-semibold mb-2">Security Analysis</h3>
            <p className="text-sm text-neutral-600">
              Automated vulnerability detection and risk assessment
            </p>
          </Card>

          <Card className="metric-card">
            <FileSearch className="w-8 h-8 mb-4 text-success-DEFAULT" />
            <h3 className="text-lg font-semibold mb-2">License Compliance</h3>
            <p className="text-sm text-neutral-600">
              Identify and manage open-source license obligations
            </p>
          </Card>

          <Card className="metric-card">
            <GitBranch className="w-8 h-8 mb-4 text-success-DEFAULT" />
            <h3 className="text-lg font-semibold mb-2">Dependency Tracking</h3>
            <p className="text-sm text-neutral-600">
              Monitor and track your software dependencies
            </p>
          </Card>
        </div>

        <div className="flex flex-col items-center justify-center p-12 border-2 border-dashed border-neutral-200 rounded-xl bg-white">
          <Upload className="w-12 h-12 text-neutral-400 mb-4" />
          <h3 className="text-xl font-semibold mb-2">Upload SBOM File</h3>
          <p className="text-sm text-neutral-600 mb-4">
            Drag and drop your SBOM file or click to browse
          </p>
          <Button className="bg-success-DEFAULT hover:bg-success-dark">
            Select File
          </Button>
        </div>
      </div>
    </div>
  );
};

export default Index;
