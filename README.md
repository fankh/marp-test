# Marp Slides Repository

## Available Slides

| Slides | Description | Link |
|--------|-------------|------|
| Python Secure Coding | Python 웹 애플리케이션 보안 개발 실습 과정 (12차시, 740분) | [View Slides](https://fankh.github.io/marp-files/) |

## Available Scripts

| Script | Description | File |
|--------|-------------|------|
| 강의 스크립트 | 슬라이드별 한국어 강의 스크립트 (강사용) | [python-secure-coding-script.md](./python-secure-coding-script.md) |

## Slides Content

### Python Secure Coding (Python 시큐어코딩)

A comprehensive secure coding curriculum for Python web applications covering:

- **01**: Secure Coding Overview & SW Development Security Methodology
- **02**: Input Validation and Output Encoding
- **03**: Command Injection
- **04**: SQL Injection
- **05**: Cross-Site Scripting (XSS)
- **06**: CSRF and Session Management
- **07**: File Upload and Path Traversal Vulnerabilities
- **08**: Serialization/Deserialization Vulnerabilities
- **09**: Authentication and Authorization
- **10**: Sensitive Data Handling and Encryption
- **11**: Error Handling and Logging Security
- **12**: Dependency and Package Supply Chain Security

## Local Preview

```bash
npm install -g @marp-team/marp-cli
marp --preview python-secure-coding.md
```

## Build Commands

```bash
# PDF
marp python-secure-coding.md -o slides.pdf

# PPTX
marp python-secure-coding.md -o slides.pptx

# HTML
marp python-secure-coding.md -o slides.html
```

## GitHub Pages Deployment

This repository uses GitHub Actions to automatically deploy slides to GitHub Pages.

- Push to `main` branch triggers the build
- Slides are deployed to: https://fankh.github.io/marp-files/
