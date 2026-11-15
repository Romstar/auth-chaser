# apt repository foundation

This directory is a stub for a future public Debian/Ubuntu repository.

Suggested layout when you stand up hosting:

```text
apt/
  conf/distributions   # from packaging/apt/distributions
  pool/
  dists/
```

Bootstrap with reprepro:

```bash
reprepro -b /var/www/apt includedeb stable dist/auth-chaser_*_amd64.deb
reprepro -b /var/www/apt export
```

Serve `/var/www/apt` over HTTPS and publish the signing public key.
