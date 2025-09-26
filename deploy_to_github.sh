#!/bin/bash
# GitHub Deployment Commands for OWASP Top 10 Scanner

echo "🚀 Deploying OWASP Top 10 Scanner to GitHub..."

# Step 1: Initialize git repository
echo "📂 Initializing Git repository..."
git init

# Step 2: Add all files
echo "📄 Adding files to Git..."
git add .

# Step 3: Initial commit
echo "💾 Creating initial commit..."
git commit -m "🎉 Initial release: OWASP Top 10 Security Scanner v1.0.0

Features:
- Comprehensive nmap integration
- OWASP Top 10 2021 vulnerability detection
- Professional reporting and JSON export
- Multi-threaded scanning capabilities
- GitHub Actions CI/CD pipeline
- Complete documentation and testing suite"

# Step 4: Add remote repository
echo "🌐 Adding GitHub remote..."
echo "⚠️  Please create repository at: https://github.com/SiteQ8/owasp-top10-scanner"
read -p "Press Enter when repository is created..."
git remote add origin https://github.com/SiteQ8/owasp-top10-scanner.git

# Step 5: Push to GitHub
echo "⬆️  Pushing to GitHub..."
git branch -M main
git push -u origin main

echo "✅ Successfully deployed to GitHub!"
echo "📋 Next steps:"
echo "1. Visit: https://github.com/SiteQ8/owasp-top10-scanner"
echo "2. Add repository description and tags"
echo "3. Enable GitHub Pages for documentation"
echo "4. Set up branch protection rules"
echo "5. Configure security alerts"

echo ""
echo "🎯 Repository Features Enabled:"
echo "- Automated testing on push/PR"
echo "- Security vulnerability scanning"
echo "- Multi-Python version support"
echo "- Automatic releases"
echo "- Issue templates"
echo "- Contributing guidelines"
