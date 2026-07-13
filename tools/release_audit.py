#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, os, re, sys, tarfile, tempfile, zipfile
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = ['pyproject.toml','README.md','CHANGELOG.md','SECURITY.md','CONTRIBUTING.md','LICENSE','install.sh','uninstall.sh','.gitignore','.mcp.json','.claude-plugin/plugin.json','.github/workflows/lint.yml','.github/workflows/release-candidate.yml','tools/build_release_bundle.py','docs/releases/README.md','docs/releases/python-0.2.0.md','docs/releases/plugin-3.0.1.md','docs/releases/release-checklist.md']
SCHEMAS = ['skill-request-v1.schema.json','skill-result-v1.schema.json','finding-v1.schema.json']
WEB_STATIC = ['index.html','app.css','app.js']
ADRS = [f'docs/adr/{i:04d}-{name}.md' for i,name in [(1,'run-manifest-and-state-log'),(2,'evidence-registry-and-integrity'),(3,'approval-registry-and-action-policy'),(4,'mcp-tool-boundary-enforcement'),(5,'skill-python-interchange-contracts'),(6,'deterministic-finding-promotion'),(7,'local-web-review-plane'),(8,'guarded-web-state-transitions')]]

def load_pyproject(path: Path) -> dict[str, object]:
    """Parse the small pyproject subset this audit needs using only stdlib."""
    data: dict[str, object] = {"project": {}, "tool": {"setuptools": {"package-data": {}}}}
    section: tuple[str, ...] = ()
    current_key: str | None = None
    current_list: list[str] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = tuple(line[1:-1].split("."))
            current_key = None
            current_list = None
            continue
        if current_list is not None:
            if line == "]":
                current_key = None
                current_list = None
                continue
            current_list.append(line.rstrip(",").strip().strip('"'))
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if value == "[":
            current_key = key
            current_list = []
            _set_pyproject_value(data, section, key, current_list)
            continue
        parsed: object
        if value.startswith('"') and value.endswith('"'):
            parsed = value.strip('"')
        elif value.startswith("[") and value.endswith("]"):
            parsed = [item.strip().strip('"') for item in value[1:-1].split(",") if item.strip()]
        else:
            parsed = value
        _set_pyproject_value(data, section, key, parsed)
    project = data.get("project", {})
    if not isinstance(project, dict) or "version" not in project:
        raise ValueError("pyproject.toml missing [project] version")
    return data


def _set_pyproject_value(data: dict[str, object], section: tuple[str, ...], key: str, value: object) -> None:
    cur: dict[str, object] = data
    for part in section:
        cur = cur.setdefault(part, {})  # type: ignore[assignment]
    cur[key] = value


@dataclass
class Check:
    name: str
    status: str
    detail: str

class Audit:
    def __init__(self, root: Path = ROOT): self.root=root; self.checks=[]
    def add(self,name,status,detail): self.checks.append(Check(name,status,detail))
    def fail(self,name,detail): self.add(name,'FAIL',detail)
    def warn(self,name,detail): self.add(name,'WARN',detail)
    def ok(self,name,detail): self.add(name,'PASS',detail)
    def versions(self):
        py=load_pyproject(self.root/'pyproject.toml')
        plugin=json.loads((self.root/'.claude-plugin/plugin.json').read_text())
        skills={}
        for p in sorted((self.root/'skills').glob('*/SKILL.md')):
            if p.parent.name=='_shared': continue
            fm=parse_frontmatter(p.read_text())[0]
            skills[p.parent.name]=str(fm.get('version'))
        schemas={p.name: json.loads(p.read_text()).get('properties',{}).get('schema_version',{}).get('const') for p in (self.root/'contracts').glob('*.schema.json')}
        return {'python_package':py['project']['version'],'claude_plugin':plugin['version'],'skills':skills,'schemas':schemas,'manifest_schema':1,'state_event_schema':1,'evidence_schema':1,'approval_schema':1,'finding_schema':schemas.get('finding-v1.schema.json')}
    def run(self):
        self.check_required_files(); self.check_parse(); self.check_versions(); self.check_skills(); self.check_schemas(); self.check_package_data(); self.check_static(); self.check_adrs(); self.check_artifacts(); self.check_security_patterns(); self.check_docs_versions(); self.check_changelog(); self.check_lint_workflow(); self.check_release_workflow(); self.check_mcp(); return self

    def check_versions(self):
        versions = self.versions()
        expected_skills = {
            'analysis-and-reporting': '1.0.0', 'cloud-and-infra': '1.1.0', 'identity-fabric': '1.0.0',
            'offensive-osint': '2.1.1', 'osint-methodology': '2.2', 'people-breach-intel': '1.0.0',
            'post-discovery': '1.0.0', 'recon-asset-discovery': '1.0.0', 'report-template': '1.0.0',
            'secrets-and-dorks': '1.0.0', 'web-surface': '1.0.0'}
        if versions['python_package'] == '0.2.0' and versions['claude_plugin'] == '3.0.1' and versions['python_package'] != versions['claude_plugin']:
            self.ok('independent release versions','Python 0.2.0 and plugin/content 3.0.1 are distinct')
        else:
            self.fail('independent release versions',f"unexpected versions: {versions['python_package']} / {versions['claude_plugin']}")
        if versions['skills'] == expected_skills:
            self.ok('skill version preservation','all 11 skill frontmatter versions match the release-readiness baseline')
        else:
            self.fail('skill version preservation','skill versions changed')
        if set(versions['schemas'].values()) == {1} and all(versions[k] == 1 for k in ['manifest_schema','state_event_schema','evidence_schema','approval_schema','finding_schema']):
            self.ok('schema version preservation','all runtime schemas remain version 1')
        else:
            self.fail('schema version preservation','schema versions changed')

    def is_bundle_root(self):
        return (self.root/"RELEASE-MANIFEST.json").exists()
    def check_required_files(self):
        required = [f for f in REQUIRED_FILES if not (self.is_bundle_root() and f.startswith((".github/", "tests/")))]
        missing=[f for f in required if not (self.root/f).exists()]
        self.ok('required repository files','all required files are present') if not missing else self.fail('required repository files','missing '+', '.join(missing))
    def check_parse(self):
        try: load_pyproject(self.root/'pyproject.toml'); self.ok('pyproject parseability','pyproject.toml parses')
        except Exception as e: self.fail('pyproject parseability',str(e))
        try: json.loads((self.root/'.claude-plugin/plugin.json').read_text()); self.ok('plugin JSON parseability','plugin metadata parses')
        except Exception as e: self.fail('plugin JSON parseability',str(e))
    def check_skills(self):
        dirs=sorted(p.parent.name for p in (self.root/'skills').glob('*/SKILL.md') if p.parent.name!='_shared')
        try: catalog=json.loads((self.root/'outrider/skill_catalog.json').read_text())['skills']
        except Exception as e: self.fail('packaged skill catalog','catalog missing or malformed: '+str(e)); catalog=[]
        if dirs==sorted(catalog): self.ok('packaged skill-catalog consistency',f'{len(dirs)} shipped skills match packaged catalog')
        else: self.fail('packaged skill-catalog consistency',f'skill dirs {dirs} != catalog {catalog}')
        bad=[]
        for p in sorted((self.root/'skills').glob('*/SKILL.md')):
            if p.parent.name=='_shared': continue
            fm,body=parse_frontmatter(p.read_text())
            for key in ['name','description','version','triggers']:
                if key not in fm: bad.append(f'{p}: missing {key}')
            if fm.get('name') != p.parent.name: bad.append(f'{p}: name mismatch')
            if not isinstance(fm.get('triggers'), list): bad.append(f'{p}: triggers must be array')
            if '../_shared/run-contract.md' not in body: bad.append(f'{p}: missing shared contract reference')
            lower=body.lower()
            if 'validated_finding' in body and not any(phrase in lower for phrase in ['do not emit','must not emit','must not finalize','must not create','must not claim']): bad.append(f'{p}: may claim validated_finding output')
        self.ok('skill frontmatter and safety',f'{len(dirs)} skill files pass deterministic checks') if not bad else self.fail('skill frontmatter and safety','; '.join(bad[:10]))
    def check_schemas(self):
        bad=[]
        for name in SCHEMAS:
            repo=self.root/'contracts'/name; pkg=self.root/'outrider/schemas'/name
            try: rd=json.loads(repo.read_text()); pd=json.loads(pkg.read_text())
            except Exception as e: bad.append(f'{name}: {e}'); continue
            if rd != pd: bad.append(f'{name}: packaged schema differs from contract')
        self.ok('JSON schema parseability','contract schemas parse and packaged copies match') if not bad else self.fail('JSON schema parseability','; '.join(bad))
    def check_package_data(self):
        py=load_pyproject(self.root/'pyproject.toml')
        data=py.get('tool',{}).get('setuptools',{}).get('package-data',{}).get('outrider',[])
        needed=['web_static/*','skill_catalog.json','schemas/*.json']
        miss=[x for x in needed if x not in data]
        self.ok('package-data declarations','web static, schemas, and skill catalog are package data') if not miss else self.fail('package-data declarations','missing '+', '.join(miss))
        deps=py['project'].get('dependencies',[]); opt=py['project'].get('optional-dependencies',{})
        if any('fastapi' in d.lower() or 'uvicorn' in d.lower() or 'httpx' in d.lower() for d in deps): self.fail('base dependency boundary','web dependencies are mandatory')
        elif all(k in opt.get('web',[]) or any(k in d for d in opt.get('web',[])) for k in ['fastapi','uvicorn','httpx']): self.ok('base dependency boundary','web dependencies remain optional')
        else: self.fail('base dependency boundary','web extra is incomplete')
    def check_static(self):
        miss=[n for n in WEB_STATIC if not (self.root/'outrider/web_static'/n).exists()]
        self.ok('web static-resource presence','index.html, app.css, and app.js are present') if not miss else self.fail('web static-resource presence','missing '+', '.join(miss))
    def check_adrs(self):
        miss=[a for a in ADRS if not (self.root/a).exists()]
        self.ok('required ADR sequence','ADR 0001 through 0008 are present') if not miss else self.fail('required ADR sequence','missing '+', '.join(miss))
    def tracked_files(self):
        import subprocess
        try: return subprocess.check_output(['git','ls-files'], cwd=self.root, text=True, stderr=subprocess.DEVNULL).splitlines()
        except Exception: return [str(p.relative_to(self.root)) for p in self.root.rglob('*') if p.is_file() and '.git' not in p.parts]
    def check_artifacts(self):
        bad=[]
        for f in self.tracked_files():
            parts=Path(f).parts
            if f.startswith(('dist/','build/')) or f.endswith(('.pyc','.egg-info/PKG-INFO')) or '__pycache__' in parts or '.venv' in parts: bad.append(f)
            if Path(f).name in {'approvals.jsonl','findings.jsonl','manifest.json'} and not f.startswith(('outrider/','tests/')): bad.append(f)
        self.ok('no obvious tracked run/build artifacts','no tracked run folders, build output, caches, or virtualenvs detected') if not bad else self.fail('no obvious tracked run/build artifacts','unexpected tracked artifacts: '+', '.join(bad[:20]))
    def check_security_patterns(self):
        patterns=[re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----'), re.compile(r'ghp_[A-Za-z0-9_]{20,}'), re.compile(r'AKIA[0-9A-Z]{16}'), re.compile(r'(?i)(password|api[_-]?key|token)\s*[:=]\s*[\"\'][^\"\']{8,}')]
        hits=[]
        for f in self.tracked_files():
            if f.startswith('.git/'): continue
            text=(self.root/f).read_text(errors='ignore')[:200000]
            for pat in patterns:
                if pat.search(text): hits.append(f); break
        
        allowed={'skills/offensive-osint/scripts/secret_scan.py','.github/workflows/lint.yml','docs/methods/opsec-infrastructure.md','docs/usage.md','examples/04-secret-hunting.md','skills/post-discovery/SKILL.md','skills/secrets-and-dorks/SKILL.md','tests/smoke-test-prompts.md'}
        unexpected=sorted(set(hits)-allowed)
        if unexpected: self.warn('obvious secret-like patterns','review possible fixtures/false positives: '+', '.join(unexpected[:20]))
        else: self.ok('obvious secret-like patterns','no unexpected secret-like patterns found; documented fixtures/examples are allowlisted')
    def check_docs_versions(self):
        doc_paths = [
            'README.md', 'docs/installation.md', 'docs/architecture.md', 'docs/release-readiness.md',
            'docs/releases/README.md', 'docs/releases/python-0.2.0.md',
            'docs/releases/plugin-3.0.1.md', 'docs/releases/release-checklist.md', 'CHANGELOG.md'
        ]
        docs = {p: (self.root / p).read_text(errors='ignore') for p in doc_paths if (self.root / p).exists()}
        combined = '\n'.join(docs.values())
        py_link = 'https://github.com/Ap6pack/outrider-recon/releases/tag/python-v0.2.0'
        plugin_link = 'https://github.com/Ap6pack/outrider-recon/releases/tag/plugin-v3.0.1'
        if py_link in combined and plugin_link in combined and 'python-v0.2.0' in combined and 'plugin-v3.0.1' in combined:
            self.ok('published release documentation links','current docs link both GitHub release tags')
        else:
            self.fail('published release documentation links','missing release tag links or tag names')
        stale_patterns = [
            'Current repository release ' + 'candidates',
            'These candidates are not ' + 'published releases',
            'No Git tags, GitHub ' + 'releases',
            'Do not create these tags ' + 'until',
            'Do not treat the unsigned candidate ' + 'as an official release',
            r'No Git tag, GitHub release',
            'does not currently enforce scope ' + 'by itself',
            'web UI are ' + 'not implemented',
            'finding' + ' validation' + chr(46) + chr(42) + 'not' + ' implemented',
            'skill-contract' + ' enforcement' + chr(46) + chr(42) + 'not' + ' implemented',
        ]
        hits=[]
        for path, text in docs.items():
            for pat in stale_patterns:
                if re.search(pat, text, re.IGNORECASE): hits.append(f'{path}: {pat}')
        if hits:
            self.fail('stale release and implementation claims','; '.join(hits[:10]))
        else:
            self.ok('stale release and implementation claims','no stale unpublished-release or implementation-status claims detected')
        forbidden_claims = [r'pip install outrider-recon==0\.2\.0', r'published to PyPI', r'PyPI publication is complete', r'Claude Marketplace publication is complete', r'published to Claude Marketplace']
        hits=[pat for pat in forbidden_claims if re.search(pat, combined, re.IGNORECASE)]
        if hits:
            self.fail('external publication claim boundaries','unexpected PyPI or Claude Marketplace publication claim: '+', '.join(hits))
        else:
            self.ok('external publication claim boundaries','docs avoid PyPI and Claude Marketplace publication claims')
        required = [
            'unsigned candidate artifacts for maintainer review',
            'does not publish automatically',
            'The same `SHA256SUMS` file covers all three',
            "grep 'outrider-recon-bundle-3.0.1.zip' SHA256SUMS | sha256sum -c -",
            "grep -E 'outrider_recon-0.2.0-py3-none-any.whl|outrider_recon-0.2.0.tar.gz' SHA256SUMS | sha256sum -c -",
        ]
        missing=[term for term in required if term not in combined]
        if missing:
            self.fail('published-vs-candidate and checksum documentation','missing '+', '.join(missing))
        else:
            self.ok('published-vs-candidate and checksum documentation','docs distinguish published releases, future candidates, and shared SHA256SUMS behavior')

    def check_changelog(self):
        text=(self.root/'CHANGELOG.md').read_text(errors='ignore')
        unreleased=text.split('## [Unreleased]',1)[1].split('---',1)[0] if '## [Unreleased]' in text else ''
        if re.search(r'## \[Python 0\.2\.0\] -- \d{4}-\d{2}-\d{2}', text) and re.search(r'## \[Claude plugin/content 3\.0\.1\] -- \d{4}-\d{2}-\d{2}', text):
            self.ok('release-domain changelog sections','Python and plugin/content sections are dated')
        else:
            self.fail('release-domain changelog sections','missing dated release-domain sections')
        released_terms=['deterministic scope checks','Claude plugin/content bundle as `3.0.1`','Python package as `0.2.0`']
        if not any(term in unreleased for term in released_terms):
            self.ok('unreleased changelog cleanup','released entries are not duplicated under Unreleased')
        else:
            self.fail('unreleased changelog cleanup','released entries remain under Unreleased')


    def check_lint_workflow(self):
        if self.is_bundle_root():
            self.ok('lint workflow exclusion','release bundle intentionally excludes .github workflow files')
            return
        path=self.root/'.github/workflows/lint.yml'
        text=path.read_text(errors='ignore') if path.exists() else ''
        problems=[]
        try:
            core_start=text.index('  python-core-tests:')
            web_start=text.index('  web-control-tests:')
            release_start=text.index('  release-readiness:')
            core=text[core_start:web_start]
            web=text[web_start:release_start]
            release=text[release_start:]
        except ValueError:
            self.fail('lint workflow test structure','missing python-core-tests, web-control-tests, or release-readiness job')
            return
        if 'python-cli-tests:' in text: problems.append('old python-cli-tests job remains')
        if 'continue-on-error' in text: problems.append('continue-on-error forbidden')
        if not re.search(r'python-version:\s*\n\s*- [\'\"]?3\.10[\'\"]?\s*\n\s*- [\'\"]?3\.11[\'\"]?\s*\n\s*- [\'\"]?3\.12[\'\"]?', core): problems.append('core matrix versions')
        if 'fail-fast: false' not in core: problems.append('core fail-fast false')
        if 'python -m pip install -e .' not in core or '.[web]' in core: problems.append('core base install boundary')
        if 'python -m compileall outrider tests mcp-server tools' not in core: problems.append('core compile command')
        if 'python -m unittest discover -s tests -p "test_*.py"' not in core: problems.append('core unittest discovery')
        if not re.search(r'python-version:\s*[\'\"]?3\.12[\'\"]?', web): problems.append('web Python 3.12')
        if 'python -m pip install -e ".[web]"' not in web: problems.append('web extra install')
        if 'python -c "import fastapi, httpx, uvicorn"' not in web: problems.append('web dependency import check')
        if 'python -m compileall outrider tests tools' not in web: problems.append('web compile command')
        if 'python -m unittest tests.test_web_view tests.test_web_app' not in web: problems.append('focused web tests')
        if 'python -m unittest discover -s tests -p "test_*.py"' not in web: problems.append('web full discovery')
        if not re.search(r'python-version:\s*[\'\"]?3\.12[\'\"]?', release): problems.append('release-readiness Python 3.12')
        if problems: self.fail('lint workflow test structure','missing or invalid '+', '.join(problems))
        else: self.ok('lint workflow test structure','base matrix, dedicated web job, and release-readiness job are configured')

    def check_release_workflow(self):
        if self.is_bundle_root():
            self.ok('release-candidate workflow exclusion','release bundle intentionally excludes .github workflow files')
            return
        path=self.root/'.github/workflows/release-candidate.yml'
        text=path.read_text(errors='ignore') if path.exists() else ''
        if 'workflow_dispatch:' in text and not re.search(r'\n\s+(push|pull_request):', text):
            self.ok('release-candidate workflow trigger','workflow_dispatch is the only trigger')
        else:
            self.fail('release-candidate workflow trigger','release workflow must be manual only')
        if re.search(r'permissions:\s*\n\s*contents:\s*read', text) and not re.search(r'contents:\s*write|packages:\s*write|id-token:\s*write|actions:\s*write', text):
            self.ok('release-candidate workflow permissions','workflow has read-only contents permission')
        else:
            self.fail('release-candidate workflow permissions','workflow must not request write permissions')
        forbidden=['pypi', 'twine upload', 'gh release create', 'git tag', 'git push', 'secrets.']
        hits=[x for x in forbidden if x in text.lower()]
        allowed=[x for x in hits if x == 'pypi' and 'no pypi' in text.lower()]
        hits=[x for x in hits if x not in allowed]
        if not hits:
            self.ok('release-candidate workflow non-publication','no publication, tag, push, or secret usage detected')
        else:
            self.fail('release-candidate workflow non-publication','forbidden terms: '+', '.join(hits))
        required=['tools/release_audit.py','unittest discover','compileall','python -m build','twine check','tools/build_release_bundle.py','SHA256SUMS','actions/upload-artifact@v4']
        missing=[x for x in required if x not in text]
        if not missing:
            self.ok('release-candidate workflow steps','candidate workflow builds, tests, checks, bundles, checksums, and uploads unsigned candidates')
        else:
            self.fail('release-candidate workflow steps','missing '+', '.join(missing))

    def check_mcp(self):
        s=(self.root/'mcp-server/server.py').read_text()
        tools=s.count('@mcp.tool')
        if tools==5 and 'run_dir' in s and 'authorize_mcp_tool' in s: self.ok('MCP tool-boundary enforcement','five tools and policy guard references detected')
        else: self.fail('MCP tool-boundary enforcement',f'expected five guarded tools, found {tools}')

def parse_frontmatter(text):
    if not text.startswith('---\n'): return {}, text
    end=text.find('\n---',4)
    if end<0: return {}, text
    fm={}; key=None
    for line in text[4:end].splitlines():
        if re.match(r'^[A-Za-z_][\w-]*:', line):
            k,v=line.split(':',1); key=k; v=v.strip()
            if v=='': fm[k]=[] if k=='triggers' else ''
            else: fm[k]=v.strip('"\'')
        elif line.strip().startswith('- ') and key:
            fm.setdefault(key,[]).append(line.strip()[2:].strip('"\''))
    return fm, text[end+4:]

def inspect_archive(path: Path):
    if path.suffix == '.whl':
        with zipfile.ZipFile(path) as z: names=z.namelist()
    else:
        with tarfile.open(path) as t: names=t.getnames()
    return {'name': path.name, 'size': path.stat().st_size, 'has_license': any(n.endswith('LICENSE') or '.dist-info/licenses/LICENSE' in n for n in names), 'has_metadata': any(n.endswith('METADATA') or n.endswith('PKG-INFO') for n in names), 'has_web_static': all(any(n.endswith('/web_static/'+x) or n.endswith('web_static/'+x) for n in names) for x in WEB_STATIC), 'has_schemas': all(any(n.endswith('/schemas/'+x) or n.endswith('schemas/'+x) or n.endswith('/contracts/'+x) for n in names) for x in SCHEMAS), 'has_skill_catalog': any(n.endswith('skill_catalog.json') for n in names), 'unexpected': [n for n in names if any(part in n for part in ['__pycache__','.venv/','/runs/','approvals.jsonl','findings.jsonl'])][:20]}

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument('--json', action='store_true'); ap.add_argument('--root', default=str(ROOT)); args=ap.parse_args(argv)
    audit=Audit(Path(args.root)).run()
    status='blocked' if any(c.status=='FAIL' for c in audit.checks) else 'ready_with_limitations' if any(c.status=='WARN' for c in audit.checks) else 'ready'
    payload={'overall_status':status,'versions':audit.versions(),'checks':[asdict(c) for c in audit.checks]}
    if args.json: print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for c in audit.checks: print(f'{c.status}: {c.name} - {c.detail}')
        print(f'Overall status: {status}')
    return 2 if status=='blocked' else 1 if status=='ready_with_limitations' else 0
if __name__=='__main__': raise SystemExit(main())
