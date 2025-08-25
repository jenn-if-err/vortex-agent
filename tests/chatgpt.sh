#!/bin/sh

curl https://api.openai.com/v1/responses \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $OPENAI_API_KEY" \
     -d '{"model": "gpt-4o","input": "'"$1"'"}'
