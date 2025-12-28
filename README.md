# Marp Slides Test

## Setup Instructions

### 1. Create Repository Structure
```
your-repo/
├── .github/
│   └── workflows/
│       └── marp.yml
├── test-slides.md
└── README.md
```

### 2. Enable GitHub Pages
1. Go to your repo → **Settings** → **Pages**
2. Source: Select **GitHub Actions**
3. Save

### 3. Push and Wait
- Push your code to `main` branch
- Go to **Actions** tab to see the build
- Once complete, your slides are live!

### 4. Access Your Slides
```
https://YOUR-USERNAME.github.io/YOUR-REPO-NAME/
```

## Local Preview
```bash
npm install -g @marp-team/marp-cli
marp --preview test-slides.md
```
