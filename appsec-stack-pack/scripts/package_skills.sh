#!/usr/bin/env bash
# package_skills.sh — produce one zip per skill in ./dist/, plus a repo zip
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="$ROOT/dist"
rm -rf "$OUT"
mkdir -p "$OUT"

SKILLS=(
  react-security
  nextjs-security
  vite-security
  vue-nuxt-security
  svelte-sveltekit-security
  angular-security
  electron-security
  nodejs-express-security
  nestjs-security
  fastify-security
  hono-security
  django-security
  fastapi-security
  flask-security
  go-security
  rails-security
  laravel-security
  spring-boot-security
  dotnet-aspnetcore-security
  graphql-security
  trpc-security
  websocket-security
  prisma-orm-security
  mongoose-mongodb-security
  redis-security
  clerk-security
  nextauth-security
  vercel-platform-security
  cloudflare-workers-security
  aws-lambda-security
)

echo "Packaging individual skills..."
for skill in "${SKILLS[@]}"; do
  if [ ! -d "$skill" ]; then
    echo "  SKIP (missing): $skill"
    continue
  fi
  # Each skill zip includes the skill folder + _shared so it's self-installable
  zip -qr "$OUT/${skill}.zip" "$skill" _shared
  echo "  packaged: $OUT/${skill}.zip"
done

echo "Packaging full repo..."
zip -qr "$OUT/appsec-stack-pack-full.zip" \
  "${SKILLS[@]}" \
  _shared \
  README.md LICENSE CONTRIBUTING.md \
  scripts \
  .github 2>/dev/null || true

echo
echo "Output: $OUT"
ls -lh "$OUT" | tail -n +2 | awk '{print "  " $9, "(" $5 ")"}'
