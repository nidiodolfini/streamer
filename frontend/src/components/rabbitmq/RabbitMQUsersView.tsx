import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Plus, RefreshCw, Search, Shield, Users } from 'lucide-react';
import { rabbitmqmanager } from '../../../wailsjs/go/models';
import {
  CreateRabbitMQUser,
  ListRabbitMQUsers,
  ListRabbitMQUserPermissions,
  ListRabbitMQVHosts,
  SetRabbitMQUserPermissions,
} from '../../../wailsjs/go/main/App';

const inputClass = 'w-full bg-[#131923] border border-[#232c3d] focus:border-rose-500 rounded-lg px-3 py-2 text-xs text-white focus:outline-none disabled:opacity-50';
const buttonClass = 'flex items-center justify-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed';
const tagShortcuts = [
  ['Admin', 'administrator'], ['Monitoring', 'monitoring'], ['Policymaker', 'policymaker'],
  ['Management', 'management'], ['Impersonator', 'impersonator'],
];
const parseTags = (value: string) => [...new Set(value.split(',').map((tag) => tag.trim()).filter(Boolean))];
const sortUsers = (users: rabbitmqmanager.RMQUserInfo[]) => [...users].sort((a, b) => a.name.localeCompare(b.name));

const Feedback: React.FC<{ error?: boolean; children: React.ReactNode }> = ({ error, children }) => (
  <div role={error ? 'alert' : 'status'} className={`flex items-start gap-2 p-3 rounded-lg border text-xs break-words ${error ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'}`}>
    {error ? <AlertTriangle className="w-4 h-4 shrink-0" /> : <CheckCircle2 className="w-4 h-4 shrink-0" />}
    <span className="min-w-0 select-text">{children}</span>
  </div>
);

export const RabbitMQUsersView: React.FC<{ isActiveTab: boolean }> = ({ isActiveTab }) => {
  const [users, setUsers] = useState<rabbitmqmanager.RMQUserInfo[]>([]);
  const [vhosts, setVhosts] = useState<string[]>([]);
  const [selectedUser, setSelectedUser] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [permissionsRevision, setPermissionsRevision] = useState(0);

  useEffect(() => {
    if (!isActiveTab) return;
    let cancelled = false;
    setLoading(true);
    setError('');
    Promise.all([ListRabbitMQUsers(), ListRabbitMQVHosts()]).then(([userList, vhostList]) => {
      if (cancelled) return;
      const nextUsers = sortUsers(userList || []);
      setUsers(nextUsers);
      setVhosts((vhostList || []).map((vhost) => vhost.name).sort());
      setSelectedUser((current) => nextUsers.some((user) => user.name === current) ? current : nextUsers[0]?.name || '');
      setPermissionsRevision((value) => value + 1);
    }).catch((err) => {
      if (!cancelled) setError(String(err));
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [isActiveTab, refresh]);

  const busy = loading || creating || saving;
  const filteredUsers = users.filter((user) => `${user.name} ${user.tags.join(',')}`.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0 bg-[#090d13] text-gray-200">
      <div className="px-6 py-5 border-b border-[#1e2530] flex items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2"><Users className="w-5 h-5 text-rose-400" />Users &amp; Permissions</h2>
          <p className="text-xs text-gray-500 mt-1">Create RabbitMQ users and manage access to each virtual host</p>
        </div>
        <button onClick={() => setRefresh((value) => value + 1)} disabled={busy}
          className="flex items-center gap-2 px-3 py-2 bg-[#141a24] border border-[#232c3d] rounded-lg text-xs disabled:opacity-50">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />Refresh
        </button>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto p-6 space-y-4">
        {error && <Feedback error>{error}</Feedback>}
        <div className="grid grid-cols-1 lg:grid-cols-[260px_minmax(0,1fr)] gap-5 items-start">
          <section className="rounded-xl border border-[#1e2530] bg-[#0c1017] overflow-hidden">
            <div className="p-4 border-b border-[#1e2530] space-y-3">
              <h3 className="text-sm font-semibold text-white">Users <span className="text-gray-500 font-normal">({users.length})</span></h3>
              <div className="relative">
                <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-gray-500" />
                <input aria-label="Search users" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search users or tags" className={`${inputClass} pl-8`} />
              </div>
            </div>
            <div className="max-h-[65vh] overflow-y-auto p-2 space-y-1">
              {loading && <p className="p-3 text-xs text-gray-500" role="status">Loading users...</p>}
              {!loading && !error && filteredUsers.length === 0 && <p className="p-3 text-xs text-gray-500">No users found.</p>}
              {!error && filteredUsers.map((user) => (
                <button key={user.name} disabled={busy} onClick={() => setSelectedUser(user.name)} aria-pressed={selectedUser === user.name}
                  className={`w-full text-left rounded-lg p-3 border transition-colors disabled:opacity-50 ${selectedUser === user.name ? 'bg-rose-500/10 border-rose-500/30' : 'border-transparent hover:bg-[#141a24]'}`}>
                  <div className="text-xs font-mono text-white break-all">{user.name}</div>
                  <div className="text-[11px] text-gray-500 mt-1 break-words">{user.tags.join(', ') || 'No tags'}</div>
                </button>
              ))}
            </div>
          </section>
          <div className="min-w-0 space-y-5">
            <AddUserForm isActiveTab={isActiveTab} disabled={loading || saving || !!error} onBusy={setCreating} onCreated={(user) => {
              setUsers((current) => sortUsers([...current.filter((item) => item.name !== user.name), user]));
              setSearch('');
              setSelectedUser(user.name);
            }} />
            {!error && selectedUser && (
              <UserPermissionsForm key={selectedUser} username={selectedUser} vhosts={vhosts}
                revision={permissionsRevision} disabled={loading || creating} onBusy={setSaving} />
            )}
            {!error && !loading && !selectedUser && <p className="text-xs text-gray-500">Add a user to set its virtual host permissions.</p>}
          </div>
        </div>
      </div>
    </div>
  );
};

const AddUserForm: React.FC<{
  isActiveTab: boolean;
  disabled: boolean;
  onBusy: (busy: boolean) => void;
  onCreated: (user: rabbitmqmanager.RMQUserInfo) => void;
}> = ({ isActiveTab, disabled, onBusy, onCreated }) => {
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [tags, setTags] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (!isActiveTab) {
      setPassword('');
      setConfirmation('');
    }
  }, [isActiveTab]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (disabled || saving) return;
    setError('');
    setSuccess('');
    if (!name.trim() || !password) { setError('Username and password are required.'); return; }
    if (password !== confirmation) { setError('Passwords do not match.'); return; }
    setSaving(true);
    onBusy(true);
    try {
      const user = await CreateRabbitMQUser(new rabbitmqmanager.CreateUserParams({ name: name.trim(), password, tags: parseTags(tags) }));
      setPassword('');
      setConfirmation('');
      setName('');
      setTags('');
      setSuccess(`User "${user.name}" created. Set its virtual host permissions below.`);
      onCreated(user);
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
      onBusy(false);
    }
  };

  const selectedTags = parseTags(tags);
  return (
    <section className="rounded-xl border border-[#1e2530] bg-[#0c1017] p-5 space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-white flex items-center gap-2"><Plus className="w-4 h-4 text-rose-400" />Add a user</h3>
        <p className="text-xs text-gray-500 mt-1">User administration requires a RabbitMQ administrator account.</p>
      </div>
      {error && <Feedback error>{error}</Feedback>}
      {success && <Feedback>{success}</Feedback>}
      <form onSubmit={submit}>
        <fieldset disabled={disabled || saving} className="space-y-4">
          <label className="block text-xs text-gray-300 space-y-1.5">
            <span>Username</span>
            <input value={name} onChange={(event) => setName(event.target.value)} className={`${inputClass} font-mono`} autoComplete="off" required />
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block text-xs text-gray-300 space-y-1.5">
              <span>Password</span>
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} className={inputClass} autoComplete="new-password" required />
            </label>
            <label className="block text-xs text-gray-300 space-y-1.5">
              <span>Confirm password</span>
              <input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} className={inputClass} autoComplete="new-password" required />
            </label>
          </div>
          <div className="space-y-2">
            <label className="block text-xs text-gray-300 space-y-1.5">
              <span>Tags</span>
              <input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="Comma-separated tags (optional)" className={`${inputClass} font-mono`} />
            </label>
            <div className="flex flex-wrap gap-2">
              {tagShortcuts.map(([label, tag]) => (
                <button type="button" key={tag} aria-pressed={selectedTags.includes(tag)}
                  onClick={() => setTags((selectedTags.includes(tag) ? selectedTags.filter((item) => item !== tag) : [...selectedTags, tag]).join(', '))}
                  className={`px-2 py-1 rounded border text-[11px] disabled:opacity-50 ${selectedTags.includes(tag) ? 'border-rose-500/40 text-rose-300 bg-rose-500/10' : 'border-[#232c3d] text-gray-400 hover:text-white'}`}>{label}</button>
              ))}
              <button type="button" onClick={() => setTags('')} aria-pressed={selectedTags.length === 0}
                className="px-2 py-1 rounded border border-[#232c3d] text-[11px] text-gray-400 hover:text-white disabled:opacity-50">None</button>
            </div>
            <p className="text-[11px] text-gray-500">Tags control management access. Configure messaging access separately per virtual host.</p>
          </div>
          <button type="submit" className={buttonClass} disabled={disabled || saving}>
            {saving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            {saving ? 'Adding user...' : 'Add user'}
          </button>
        </fieldset>
      </form>
    </section>
  );
};

const UserPermissionsForm: React.FC<{
  username: string;
  vhosts: string[];
  revision: number;
  disabled: boolean;
  onBusy: (busy: boolean) => void;
}> = ({ username, vhosts, revision, disabled, onBusy }) => {
  const [permissions, setPermissions] = useState<rabbitmqmanager.RMQUserPermissions[]>([]);
  const [vhost, setVhost] = useState(vhosts.includes('/') ? '/' : vhosts[0] || '');
  const [patterns, setPatterns] = useState({ configure: '.*', write: '.*', read: '.*' });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadError('');
    setError('');
    setSuccess('');
    ListRabbitMQUserPermissions(username).then((list) => {
      if (!cancelled) setPermissions(list || []);
    }).catch((err) => {
      if (!cancelled) setLoadError(String(err));
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [username, revision]);

  useEffect(() => {
    setVhost((current) => vhosts.includes(current) ? current : vhosts.includes('/') ? '/' : vhosts[0] || '');
  }, [vhosts]);

  useEffect(() => {
    const existing = permissions.find((permission) => permission.vhost === vhost);
    setPatterns(existing ? { configure: existing.configure, write: existing.write, read: existing.read } : { configure: '.*', write: '.*', read: '.*' });
    setError('');
  }, [permissions, vhost]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (disabled || loading || saving || loadError || !vhost) return;
    setSaving(true);
    onBusy(true);
    setError('');
    setSuccess('');
    const params = new rabbitmqmanager.RMQUserPermissions({ user: username, vhost, ...patterns });
    try {
      await SetRabbitMQUserPermissions(params);
      // Update the confirmed grant locally so a failed follow-up read cannot
      // turn a successful mutation into an apparent failure.
      setPermissions((current) => [...current.filter((item) => item.vhost !== params.vhost), params].sort((a, b) => a.vhost.localeCompare(b.vhost)));
      setSuccess(`Permissions saved for "${username}" in "${params.vhost}".`);
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
      onBusy(false);
    }
  };

  return (
    <section className="rounded-xl border border-[#1e2530] bg-[#0c1017] p-5 space-y-4">
      <h3 className="text-sm font-semibold text-white flex items-start gap-2"><Shield className="w-4 h-4 shrink-0 text-rose-400" /><span>Permissions for <span className="font-mono text-rose-300 break-all select-text">{username}</span></span></h3>
      {loading && <p role="status" className="text-xs text-gray-500">Loading permissions...</p>}
      {loadError && <Feedback error>{loadError}</Feedback>}
      {!loading && !loadError && (
        <div className="overflow-x-auto rounded-lg border border-[#1e2530]">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#101620] text-gray-400"><tr>{['Virtual host', 'Configure', 'Write', 'Read', ''].map((label) => <th key={label} className="p-2.5 font-medium">{label}</th>)}</tr></thead>
            <tbody>
              {permissions.length === 0 && <tr><td colSpan={5} className="p-3 text-gray-500">This user has no virtual host permissions.</td></tr>}
              {permissions.map((permission) => (
                <tr key={permission.vhost} className="border-t border-[#1e2530]">
                  {[permission.vhost, permission.configure, permission.write, permission.read].map((value, index) => <td key={index} className="p-2.5 font-mono select-text break-all min-w-[80px]">{value === '' ? <span className="text-gray-600 italic">(empty)</span> : value}</td>)}
                  <td className="p-2.5"><button type="button" disabled={disabled || saving || !vhosts.includes(permission.vhost)} className="text-rose-400 hover:text-rose-300 disabled:opacity-50" aria-label={`Edit permissions in ${permission.vhost}`} onClick={() => {
                    setVhost(permission.vhost);
                    setPatterns({ configure: permission.configure, write: permission.write, read: permission.read });
                    setError('');
                    setSuccess('');
                  }}>Edit</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {error && <Feedback error>{error}</Feedback>}
      {success && <Feedback>{success}</Feedback>}
      <form onSubmit={submit}>
        <fieldset disabled={disabled || loading || saving || !!loadError || vhosts.length === 0} className="space-y-4">
          <h4 className="text-xs font-semibold text-white">Set permission</h4>
          <label className="block text-xs text-gray-300 space-y-1.5">
            <span>Virtual host</span>
            <select value={vhost} onChange={(event) => { setVhost(event.target.value); setSuccess(''); }} className={`${inputClass} font-mono`} required>
              {vhosts.length === 0 && <option value="">No virtual hosts available</option>}
              {vhosts.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </label>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
            {(['configure', 'write', 'read'] as const).map((field) => (
              <label key={field} className="block text-xs text-gray-300 space-y-1.5">
                <span>{field[0].toUpperCase() + field.slice(1)} regexp</span>
                <input value={patterns[field]} spellCheck={false} onChange={(event) => {
                  setPatterns((current) => ({ ...current, [field]: event.target.value }));
                  setSuccess('');
                }} className={`${inputClass} font-mono`} />
              </label>
            ))}
          </div>
          <p className="text-[11px] text-gray-500">Patterns match resource names: <code>.*</code> matches all. Saving replaces all three patterns for this virtual host. RabbitMQ validates the expressions.</p>
          <button type="submit" className={buttonClass} disabled={disabled || loading || saving || !!loadError || !vhost}>
            {saving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
            {saving ? 'Saving...' : 'Set permission'}
          </button>
        </fieldset>
      </form>
    </section>
  );
};
