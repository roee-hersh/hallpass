"""Checks every relative link and #anchor in the repository's Markdown files.

    python3 test/docs/linkcheck.py

Run from the repository root. Exits 1 and lists each broken link.
"""
import re,os,glob,sys
def slug(h):
    h=h.strip().lower()
    h=re.sub(r'[^\w\- ]','',h)
    return h.replace(' ','-')
def anchors(path):
    try: s=open(path).read()
    except: return set()
    s=re.sub(r'```.*?```','',s,flags=re.S)
    return {slug(m) for m in re.findall(r'^#+\s+(.*)$',s,re.M)}
bad=0
for f in glob.glob('**/*.md',recursive=True):
    if 'node_modules' in f or f.startswith(('.specs/', 'dist/')): continue
    s=open(f).read()
    s2=re.sub(r'```.*?```','',s,flags=re.S)
    for m in re.finditer(r'\]\(([^)\s]+)\)',s2):
        link=m.group(1)
        if link.startswith(('http://','https://','mailto:')): continue
        path,_,frag=link.partition('#')
        target=os.path.normpath(os.path.join(os.path.dirname(f),path)) if path else f
        if path and not os.path.exists(target):
            print(f'{f}: missing {link}'); bad+=1; continue
        if frag and target.endswith('.md') and frag not in anchors(target):
            print(f'{f}: bad anchor {link}'); bad+=1
print(f'{bad} broken links' if bad else 'all links resolve')
sys.exit(1 if bad else 0)
