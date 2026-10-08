# Homelab notes

## git push rejected after history rewrite

```
$ git push
 ! [rejected]        main -> main (non-fast-forward)
error: failed to push some refs to 'origin'
```

The remote has commits that the local branch lost during the rebase.

1. Fetch and inspect: `git fetch origin && git log --oneline main..origin/main`
2. If the remote commits are expendable, `git push --force-with-lease origin main`

## Docker build fails on arm64 with exec format error

```
#8 0.412 exec /bin/sh: exec format error
```

The base image was pulled for amd64 only. Rebuild with `docker buildx build --platform linux/arm64 .` using Docker 26.1.
