class YAMLError(Exception): pass
class nodes:
    class MappingNode: pass
class resolver:
    class BaseResolver:
        DEFAULT_MAPPING_TAG='tag:yaml.org,2002:map'
class SafeLoader:
    @classmethod
    def add_constructor(cls,*a,**k): pass

def _scalar(v):
    v=v.strip()
    if v == '[]': return []
    if v == '{}': return {}
    if v.lower() in ('true','false'): return v.lower()=='true'
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    if v.startswith('[') and not v.endswith(']'):
        raise YAMLError('malformed YAML: unterminated list')
    if v.startswith('[') and v.endswith(']'):
        inner=v[1:-1].strip()
        if not inner: return []
        return [_scalar(x.strip()) for x in inner.split(',')]
    try: return int(v)
    except ValueError: pass
    return v

def load(text, Loader=None):
    root={}; lines=text.splitlines(); i=0
    while i < len(lines):
        raw=lines[i]
        if not raw.strip() or raw.lstrip().startswith('#'):
            i+=1; continue
        if raw.startswith(' '): raise YAMLError('malformed YAML: unexpected indentation')
        if ':' not in raw: raise YAMLError('malformed YAML: expected key')
        key,val=raw.split(':',1); key=key.strip(); val=val.strip()
        if key in root: raise YAMLError(f'duplicate YAML key: {key}')
        if val:
            root[key]=_scalar(val); i+=1; continue
        i+=1; arr=[]; mapping={}; saw=False; mode=None
        while i < len(lines):
            l=lines[i]
            if not l.strip(): i+=1; continue
            if not l.startswith(' '): break
            st=l.strip(); saw=True
            if st.startswith('- '):
                if mode in (None,'list'): mode='list'; arr.append(_scalar(st[2:]))
                else: raise YAMLError('malformed YAML: mixed nested types')
            elif ':' in st:
                if mode in (None,'map'):
                    mode='map'; k2,v2=st.split(':',1); mapping[k2.strip()]=_scalar(v2.strip())
                else: raise YAMLError('malformed YAML: mixed nested types')
            else:
                if mode is None:
                    mode='scalar'; mapping['__value__']=_scalar(st)
                else: raise YAMLError('malformed YAML: unsupported nested value')
            i+=1
        root[key]= arr if mode=='list' or not saw else (mapping['__value__'] if mode=='scalar' else mapping)
    return root
