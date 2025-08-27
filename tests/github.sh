#!/bin/sh

curl \
    -L \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer garbage.invalid.value" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/app/installations/nothing/access_tokens \
    -d '{"repositories":["prism"],"permissions":{"issues":"read","contents":"read"}}'
