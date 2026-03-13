# Q-ARMOR Architecture (March 2026)

## Overview

Q-ARMOR is a mode-aware PQC assessment platform with a unified backend pipeline that supports both demo and live scans.

- Presentation: landing page and dashboard (`frontend/landing.html`, `frontend/index.html`)
- API layer: FastAPI app with static mounting and dashboard alias routes (`backend/app.py`)
- Pipeline layer: single orchestration flow for demo/live execution (`backend/pipeline.py`)
- Scanner layer: discovery, probing, negotiation analysis, classification, regression, labeling, attestation
- Persistence: SQLite (`data/scanner.db`) plus in-memory latest result cache

## Architecture Diagram

```mermaid
graph TB
    subgraph "Client Layer"
        Landing["Landing /static/landing.html"]
        Dashboard["Dashboard / and /dashboard"]
        CLI["CLI scan.py"]
    end

    subgraph "Backend"
        API["FastAPI app.py"]
        Cache["Latest pipeline cache (mode/domain)"]
        Pipeline["run_pipeline(mode, domain)"]

        subgraph "Scanner Modules"
            Discoverer["discoverer.py"]
            Prober["prober.py"]
            Negotiation["negotiation_policy.py"]
            Classifier["classifier.py + agility_assessor.py"]
            Regression["regression_detector.py"]
            CBOM["cbom_generator.py"]
            Labeling["labeler.py + label_registry.py"]
            Attestor["attestor.py"]
            Notifier["notifier.py"]
            Rating["cyber_rating.py"]
        end
    end

    subgraph "Data"
        Demo["Demo fixtures"]
        DB["SQLite scanner.db"]
        Keys[".keys signing keys"]
    end

    subgraph "External"
        Targets["DNS/CT/TLS endpoints"]
        Hooks["Slack/Teams"]
    end

    Landing --> Dashboard
    Dashboard --> API
    CLI --> API
    API --> Cache
    API --> Pipeline
    Pipeline --> Discoverer --> Targets
    Pipeline --> Prober --> Targets
    Pipeline --> Negotiation
    Pipeline --> Classifier
    Pipeline --> Regression
    Pipeline --> CBOM
    Pipeline --> Labeling
    Pipeline --> Attestor --> Keys
    Pipeline --> Notifier --> Hooks
    Pipeline --> Rating
    Pipeline --> Demo
    Pipeline --> DB
```

## Runtime Flow

1. Client calls mode-aware API (`mode=demo|live`, optional `domain`).
2. Backend checks cached pipeline context.
3. On cache miss/refresh, backend executes unified pipeline.
4. Pipeline returns a single `PipelineResult` payload (assets, heatmap, rating, CBOM, labels, attestation, alerts).
5. UI widgets and report endpoints derive their data from the latest pipeline result.
