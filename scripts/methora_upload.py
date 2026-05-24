#!/usr/bin/env python3
"""
methora_upload.py - bulk-upload every skill in this repo to Methora.

Reads the token from $METHORA_TOKEN. Never persists or echoes the token.

Usage:
    METHORA_TOKEN=lit_pat_... python scripts/methora_upload.py [--dry-run] [--only SKILL]

For each skill folder:
  - parses SKILL.md frontmatter (name, description)
  - splits frontmatter from body; the body becomes the `directive`
  - walks references/, scripts/, assets/ into the `references[]` array
  - inlines _shared/ files into references/_shared/ inside the skill
  - rewrites `../_shared/` -> `_shared/` in the directive so paths resolve
  - extracts trigger phrases from the description for `triggers[]`
  - POSTs to Methora's create_skill MCP tool
"""

import argparse
import json
import os
import re
import sys
import urllib.request

METHORA_BASE = "https://qletndspniubnyrogiax.supabase.co/functions/v1/skills-mcp"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_yaml_frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.DOTALL)
    if not m:
        return None, text
    import yaml
    return yaml.safe_load(m.group(1)), m.group(2).lstrip()


def extract_triggers(description: str, skill_name: str) -> list:
    """Pull quoted phrases out of the description as triggers."""
    triggers = []
    # Find quoted phrases (single or double quotes)
    for m in re.finditer(r"['\"]([^'\"]{3,60})['\"]", description):
        phrase = m.group(1).strip()
        if phrase and phrase not in triggers and not phrase.startswith("@") and "://" not in phrase:
            triggers.append(phrase)
    # Always include the skill name as a trigger
    if skill_name not in triggers:
        triggers.insert(0, skill_name)
    return triggers[:12]  # cap


def first_sentence(text: str) -> str:
    text = text.strip()
    m = re.search(r"^(.+?[.!?])(?:\s|$)", text)
    return (m.group(1) if m else text)[:240]


def collect_references(skill_dir: str, pack_root: str) -> list:
    """Collect references/, scripts/, assets/, and inlined _shared/ into refs[]."""
    refs = []

    def add_dir(subdir: str, path_prefix: str):
        full = os.path.join(skill_dir, subdir)
        if not os.path.isdir(full):
            return
        for root, _, files in os.walk(full):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, skill_dir).replace(os.sep, "/")
                # Limit to reasonable file types
                if fname.startswith(".") or fname.endswith((".bak", ".pyc")):
                    continue
                try:
                    with open(fpath, encoding="utf-8") as f:
                        content = f.read()
                except UnicodeDecodeError:
                    # Skip non-text files (rare but possible)
                    continue
                refs.append({"path": rel, "content": content})

    add_dir("references", "references/")
    add_dir("scripts", "scripts/")
    add_dir("assets", "assets/")

    # Inline _shared/ from the pack root
    shared = os.path.join(pack_root, "_shared")
    if os.path.isdir(shared):
        for fname in sorted(os.listdir(shared)):
            fpath = os.path.join(shared, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, encoding="utf-8") as f:
                    content = f.read()
                refs.append({"path": f"_shared/{fname}", "content": content})
            except UnicodeDecodeError:
                continue

    return refs


def build_payload(skill_dir: str, pack_root: str, pack_name: str) -> dict:
    skill_md = os.path.join(skill_dir, "SKILL.md")
    with open(skill_md, encoding="utf-8") as f:
        raw = f.read()
    meta, body = load_yaml_frontmatter(raw)
    if not meta or not meta.get("name") or not meta.get("description"):
        raise ValueError(f"{skill_md}: missing name or description")

    name = meta["name"]
    description = meta["description"]
    skill_folder = os.path.basename(skill_dir)
    assert name == skill_folder, f"name {name!r} != folder {skill_folder!r}"

    # The directive is the SKILL.md body (frontmatter stripped).
    # Rewrite ../_shared/ refs so paths resolve when references are inlined.
    directive = body.replace("../_shared/", "_shared/")

    category = {
        "saas-security-pack": "saas-security",
        "appsec-stack-pack": "appsec-stack",
    }.get(pack_name, "security")

    payload = {
        "name": name,
        "summary": first_sentence(description),
        "category": category,
        "directive": directive,
        "references": collect_references(skill_dir, pack_root),
        "triggers": extract_triggers(description, name),
        "auto_advertise": False,  # don't expose as first-class MCP tool by default
    }
    return payload


def call_mcp(method: str, args: dict, token: str) -> dict:
    url = f"{METHORA_BASE}?token={token}"
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": method, "arguments": args}}
    ).encode("utf-8")
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": {"code": e.code, "message": e.read().decode("utf-8")}}
    except Exception as e:
        return {"error": {"code": 0, "message": str(e)}}


def discover_skills() -> list:
    out = []
    for pack in ("saas-security-pack", "appsec-stack-pack"):
        pack_root = os.path.join(REPO_ROOT, pack)
        for entry in sorted(os.listdir(pack_root)):
            path = os.path.join(pack_root, entry)
            if not os.path.isdir(path):
                continue
            if entry.startswith("_") or entry.startswith(".") or entry == "scripts":
                continue
            if os.path.isfile(os.path.join(path, "SKILL.md")):
                out.append((pack, pack_root, path))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="Build payloads but don't POST")
    ap.add_argument("--only", help="Upload only this skill name (for testing)")
    args = ap.parse_args()

    token = os.environ.get("METHORA_TOKEN")
    if not token and not args.dry_run:
        print("ERROR: set METHORA_TOKEN env var", file=sys.stderr)
        sys.exit(2)

    skills = discover_skills()
    if args.only:
        skills = [s for s in skills if os.path.basename(s[2]) == args.only]
        if not skills:
            print(f"ERROR: skill {args.only} not found", file=sys.stderr)
            sys.exit(2)

    print(f"Discovered {len(skills)} skills{' (DRY RUN)' if args.dry_run else ''}")
    results = []
    for pack_name, pack_root, skill_dir in skills:
        name = os.path.basename(skill_dir)
        try:
            payload = build_payload(skill_dir, pack_root, pack_name)
        except Exception as e:
            print(f"  SKIP {name}: build failed: {e}")
            results.append((name, "build-failed", str(e)))
            continue

        ref_count = len(payload["references"])
        directive_len = len(payload["directive"])
        trig_count = len(payload["triggers"])

        if args.dry_run:
            print(f"  DRY {name:<32} dir={directive_len:>5}c refs={ref_count:>2} triggers={trig_count}")
            continue

        resp = call_mcp("create_skill", payload, token)
        if "error" in resp:
            print(f"  FAIL {name}: {resp['error']}")
            results.append((name, "fail", str(resp["error"])))
            continue
        result = resp.get("result", {})
        # Extract skill id from response
        skill_id = None
        sc = result.get("structuredContent") or {}
        if isinstance(sc, dict):
            skill_id = sc.get("id") or sc.get("skill_id")
        # Sometimes id is in content text
        if not skill_id and "content" in result:
            for c in result.get("content") or []:
                t = c.get("text", "")
                m = re.search(r'\b(skill[_-]?id|id)["\s:]+([a-zA-Z0-9-]{6,})', t)
                if m:
                    skill_id = m.group(2)
                    break
        print(f"  OK   {name:<32} dir={directive_len:>5}c refs={ref_count:>2} id={skill_id}")
        results.append((name, "ok", skill_id))

    # Summary
    if not args.dry_run:
        print()
        ok = sum(1 for _, s, _ in results if s == "ok")
        fail = sum(1 for _, s, _ in results if s != "ok")
        print(f"Created: {ok}/{len(results)}  Failed: {fail}")
        # Write manifest (without token)
        manifest_path = os.path.join(REPO_ROOT, "scripts", "methora_upload_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump([{"name": n, "status": s, "id": i} for n, s, i in results],
                      f, indent=2)
        print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
