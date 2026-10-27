import React, { useEffect, useRef, useState } from 'react';
import { Check, AlertTriangle, Save, Zap } from 'lucide-react';
import { GetSSHBastions, SaveSSHBastion, TestSSHBastion } from '../../wailsjs/go/main/App';
import { storage } from '../../wailsjs/go/models';

interface Props {
  profile: storage.ConnectionProfile;
  onApply: (bastion: storage.SSHBastion) => void;
}

const settingsFromProfile = (p: storage.ConnectionProfile) => ({
  host: (p.sshHost || '').trim(),
  port: p.sshPort || 22,
  user: (p.sshUser || '').trim(),
  authMethod: p.sshAuthMethod || 'key',
  password: (p.sshAuthMethod || 'key') === 'password' ? (p.sshPassword || '') : '',
  keyFile: (p.sshAuthMethod || 'key') === 'key' ? (p.sshKeyFile || '').trim() : '',
  keyPassphrase: (p.sshAuthMethod || 'key') === 'key' ? (p.sshKeyPassphrase || '') : '',
});

export const SSHBastionPresets: React.FC<Props> = ({ profile, onApply }) => {
  const [bastions, setBastions] = useState<storage.SSHBastion[]>([]);
  const [selectedID, setSelectedID] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const mounted = useRef(false);
  const settings = settingsFromProfile(profile);
  const signature = JSON.stringify(settings);
  const currentSignature = useRef(signature);
  currentSignature.current = signature;

  useEffect(() => {
    mounted.current = true;
    let canceled = false;
    GetSSHBastions().then((list) => {
      if (canceled) return;
      setBastions(list || []);
      const match = (list || []).find((b) =>
        Object.entries(settings).every(([key, value]) => (b[key as keyof storage.SSHBastion] || '') === value)
      );
      if (match) {
        setSelectedID(match.id);
        setName(match.name);
      }
    }).catch((err) => {
      if (!canceled) setResult({ ok: false, msg: `Could not load saved bastions: ${String(err)}` });
    }).finally(() => {
      if (!canceled) setLoading(false);
    });
    return () => { canceled = true; mounted.current = false; };
  }, []);

  useEffect(() => { setResult(null); }, [signature]);

  const apply = (id: string) => {
    setSelectedID(id);
    setResult(null);
    const b = bastions.find((item) => item.id === id);
    setName(b?.name || '');
    if (b) onApply(b);
  };

  const run = async (save: boolean) => {
    const b = storage.SSHBastion.createFrom({
      ...settings, id: selectedID || crypto.randomUUID(), name: name.trim(),
    });
    const testedSignature = signature;
    let saved = false;
    setBusy(save ? 'save' : 'test');
    setResult(null);
    try {
      if (save) {
        await SaveSSHBastion(b);
        saved = true;
        if (mounted.current) {
          setSelectedID(b.id);
          setBastions((prev) => [...prev.filter((item) => item.id !== b.id), b]
            .sort((a, other) => a.name.localeCompare(other.name)));
        }
      }
      const elapsed = await TestSSHBastion(b);
      if (mounted.current && currentSignature.current === testedSignature) {
        setResult({ ok: true, msg: `${saved ? 'Bastion saved. ' : ''}SSH authenticated (${elapsed.toFixed(0)} ms). Use Test Ping to also verify the broker through this bastion.` });
      }
    } catch (err) {
      if (mounted.current && currentSignature.current === testedSignature) {
        setResult({ ok: false, msg: `${saved ? 'Bastion saved; SSH test failed. ' : ''}${String(err)}` });
      }
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  return (
    <div className="p-4 rounded-lg bg-[#111722] border border-[#1e2736] space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <label htmlFor="savedBastion" className="text-xs font-medium text-gray-300">Saved bastions</label>
          <select id="savedBastion" value={selectedID} onChange={(e) => apply(e.target.value)} disabled={loading || !!busy}
            className="w-full bg-[#131923] border border-[#232c3d] rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500 disabled:opacity-50">
            <option value="">{loading ? 'Loading...' : 'New bastion / current settings'}</option>
            {bastions.map((b) => <option key={b.id} value={b.id}>{b.name} — {b.user}@{b.host}:{b.port}</option>)}
          </select>
        </div>
        <div className="space-y-1.5">
          <label htmlFor="bastionName" className="text-xs font-medium text-gray-300">Bastion name</label>
          <input id="bastionName" value={name} onChange={(e) => setName(e.target.value)} disabled={!!busy}
            placeholder="e.g. AWS production bastion"
            className="w-full bg-[#131923] border border-[#232c3d] rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500 disabled:opacity-50" />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button type="button" onClick={() => run(true)} disabled={loading || !!busy || !name.trim() || !settings.host || !settings.user}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50">
          <Save className="w-3.5 h-3.5" />{busy === 'save' ? 'Saving & testing...' : 'Save & Test Bastion'}
        </button>
        <button type="button" onClick={() => run(false)} disabled={!!busy || !settings.host || !settings.user}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium text-gray-300 bg-[#1a212d] hover:bg-[#232c3c] border border-[#2a3446] disabled:opacity-50">
          <Zap className={`w-3.5 h-3.5 text-amber-400 ${busy === 'test' ? 'animate-bounce' : ''}`} />{busy === 'test' ? 'Testing SSH...' : 'Test SSH'}
        </button>
        {busy && <span className="text-[11px] text-gray-500">SSH timeout: 15 seconds</span>}
      </div>
      <p className="text-[11px] text-gray-500">
        Save the SSH fields below once, then select this bastion in any connection. Selection copies its settings; use Save above to keep them in the connection profile. Choose New to save a separate bastion.
      </p>
      {result && (
        <div role="status" className={`flex items-start gap-2 text-xs ${result.ok ? 'text-emerald-400' : 'text-rose-400'}`}>
          {result.ok ? <Check className="w-4 h-4 shrink-0" /> : <AlertTriangle className="w-4 h-4 shrink-0" />}
          <span className="break-words min-w-0">{result.msg}</span>
        </div>
      )}
    </div>
  );
};
