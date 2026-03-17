#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║  AGENTIC PLATFORM — GCP Cloud Run Deploy Script         ║
# ║  Run this from Cloud Shell or any machine with gcloud   ║
# ╚══════════════════════════════════════════════════════════╝

# ── 1. Set your project ───────────────────────────────────────
PROJECT_ID="your-gcp-project-id"        # ← CHANGE THIS
REGION="us-central1"                    # ← change region if needed
SERVICE_NAME="agentic-platform"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "🚀 Deploying Agentic Platform to GCP Cloud Run"
echo "   Project : $PROJECT_ID"
echo "   Region  : $REGION"
echo "   Service : $SERVICE_NAME"
echo ""

# ── 2. Set project ────────────────────────────────────────────
gcloud config set project $PROJECT_ID

# ── 3. Enable required APIs ───────────────────────────────────
gcloud services enable \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  containerregistry.googleapis.com

# ── 4. Build & push container image ──────────────────────────
echo "📦 Building container image..."
gcloud builds submit --tag $IMAGE .

# ── 5. Deploy to Cloud Run ────────────────────────────────────
echo "☁️  Deploying to Cloud Run..."
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --port 8080 \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 3 \
  --timeout 300 \
  --set-env-vars PORT=8080

# ── 6. Get the URL ────────────────────────────────────────────
URL=$(gcloud run services describe $SERVICE_NAME \
  --platform managed \
  --region $REGION \
  --format 'value(status.url)')

echo ""
echo "✅ DEPLOYED SUCCESSFULLY"
echo "   URL: $URL"
echo ""
echo "   Share this URL with your team."
echo "   The dashboard updates live every ~0.8s via SSE."
