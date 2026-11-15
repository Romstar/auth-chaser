# dnf / yum repository foundation

This directory is a stub for a future Fedora/RHEL repository or COPR project.

Local repo from CI artifacts:

```bash
mkdir -p /srv/rpm/9/x86_64
cp dist/*.rpm /srv/rpm/9/x86_64/
createrepo_c /srv/rpm/9/x86_64
```

Publish `auth-chaser.repo` (this folder) with a real `baseurl` and GPG key URL.

COPR alternative: create a project at https://copr.fedorainfracloud.org/ and point it at this GitHub repository once an RPM spec or nfpm pipeline is wired for automatic builds.
