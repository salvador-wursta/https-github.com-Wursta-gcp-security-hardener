# GCP Security Hardener - Project Structure

## Complete File Tree

```
gcp-security-hardener/
├── .gitignore                          # Git ignore rules
├── README.md                           # Main project documentation
├── PROJECT_STRUCTURE.md                # This file
│
├── frontend/                           # Next.js 14 Application
│   ├── .env.example                    # Environment variables template
│   ├── .eslintrc.json                  # ESLint configuration
│   ├── package.json                    # Node.js dependencies
│   ├── tsconfig.json                   # TypeScript configuration
│   ├── next.config.js                  # Next.js configuration
│   ├── tailwind.config.js              # Tailwind CSS configuration
│   ├── postcss.config.js               # PostCSS configuration
│   │
│   ├── app/                            # Next.js App Router
│   │   ├── layout.tsx                  # Root layout component
│   │   ├── page.tsx                    # Home page
│   │   ├── globals.css                 # Global styles with Tailwind
│   │   └── wizard/                     # Needs Assessment Wizard
│   │       └── page.tsx                # Wizard page (Phase 2, Step 1)
│   │
│   ├── components/                     # React components
│   │   └── __init__.ts                 # Components directory marker
│   │
│   └── lib/                            # Utility functions
│       └── __init__.ts                 # Lib directory marker
│
└── backend/                            # FastAPI Application
    ├── .env.example                    # Environment variables template
    ├── .dockerignore                   # Docker ignore rules
    ├── Dockerfile                      # Cloud Run deployment config
    ├── requirements.txt                # Python dependencies
    │
    └── app/                            # FastAPI application
        ├── __init__.py                 # Package marker
        ├── main.py                     # FastAPI app entry point
        │
        ├── models/                     # Pydantic models
        │   └── __init__.py             # Models package marker
        │
        └── services/                   # GCP service integrations
            └── __init__.py             # Services package marker
```

## Key Dependencies

### Frontend (package.json)
- **Next.js 14.2.0** - React framework with App Router
- **React 18.3.0** - UI library
- **Firebase 10.12.0** - Authentication
- **Tailwind CSS 3.4.1** - Styling
- **Lucide React 0.344.0** - Icons
- **Zod 3.22.4** - Schema validation
- **React Hook Form 7.51.0** - Form management

### Backend (requirements.txt)
- **FastAPI 0.109.0** - Web framework
- **Uvicorn 0.27.0** - ASGI server
- **Pydantic 2.5.3** - Data validation
- **Google Cloud Libraries**:
  - Resource Manager
  - Billing & Budgets
  - Service Usage
  - IAM
  - Recommender
  - Logging
  - Pub/Sub
- **Firebase Admin 6.4.0** - Token verification
- **ReportLab 4.1.0** - PDF generation

## Next Steps (Phase 2)

1. ✅ **Step 1: Project Structure** - COMPLETED
2. ⏳ **Step 2: OAuth Flow** - Implement Google Identity Services
3. ⏳ **Step 3: Deep Scan** - Backend GCP API integration
4. ⏳ **Step 4: Template Selection & Lockdown** - Security policy enforcement

## Development Commands

### Frontend
```bash
cd frontend
npm install          # Install dependencies
npm run dev          # Start development server (localhost:3000)
npm run build        # Build for production
npm run start        # Start production server
```

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload  # Start development server (localhost:8000)
```

## Environment Setup

1. Copy `.env.example` to `.env` in both `frontend/` and `backend/`
2. Configure Firebase project credentials
3. Set up GCP service account with required permissions
4. Configure backend CORS origins in `app/main.py`

