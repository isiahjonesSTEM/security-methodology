# GitHub Actions workflows

Automation that builds and publishes this repository's GitHub Pages site.

## Files

- `build-and-deploy-v2.yml` — on every push to `main` (or a manual run) it:
  1. Checks out the repository.
  2. Replaces the Stripe placeholders in `pricing.md` and `manage.md` with values held in repository secrets (no keys are stored in the repository).
  3. Builds the Jekyll site (`_config.yml`, theme `jekyll-theme-cayman`).
  4. Uploads the built site and deploys it to GitHub Pages: https://isiahjonesstem.github.io/security-methodology/

Change the workflow only if the site build or the payment placeholders change.
