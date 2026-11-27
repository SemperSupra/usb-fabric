# Public documentation and release delivery

The documentation site is deliberately separate from build artifacts and product release acceptance.

## Reproduce the site

Use Python 3, with no network dependencies:

```sh
python3 -I scripts/build-public-pages.py /tmp/public-site-new
python3 -m http.server 8000 --directory /tmp/public-site-new
```

The output directory must be new. Only the reviewed site/index.html is materialized. Review changes to the allowlist and workflow as release-boundary changes. The validator is a narrow content check, not a general-purpose secret scanner or HTML sanitizer.

## GitHub Actions and Pages

Pull requests run the read-only site validation on a standard hosted Ubuntu runner. A push to main affecting the documentation files, or a manual workflow dispatch on main, builds and deploys the approved documentation. The deployment job alone receives Pages and OIDC permissions. In repository Settings > Pages, select GitHub Actions as the source; if Pages is unavailable, the deployment is blocked, not silently bypassed.

The site announces no product release. Public product releases require applicable licensing notices, standalone build/test instructions, exact-source qualification evidence and approved packages with checksums. Do not add experimental logs, private coordination records, sensitive data, or unqualified binaries to the site or release assets. A passed documentation workflow is not product qualification.

Rollback: revert the reviewed documentation commit on main and redeploy. Disable Pages through repository settings if immediate removal is necessary.
