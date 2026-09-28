const API=import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
async function request(path, options={}){const r=await fetch(API+path,{headers:{'Content-Type':'application/json'},...options}); if(!r.ok){let d={};try{d=await r.json()}catch{} throw new Error(d.detail||'Request failed')} return r.json();}
export const getDashboard=()=>request('/dashboard');
export const scan=(type,input)=>request('/scan/'+type,{method:'POST',body:JSON.stringify({input})});
export const reportUrl=(id)=>`${API}/reports/${id}.pdf`;
export const getSettings=()=>request('/settings');
export const updateSettings=(settings)=>request('/settings',{method:'PUT',body:JSON.stringify(settings)});
export const threatIntelLookup=(target)=>request('/threat-intelligence/lookup',{method:'POST',body:JSON.stringify({target})});
