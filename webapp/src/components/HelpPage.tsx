export default function HelpPage() {
  return (
    <div className="stack">
      <section className="card">
        <h3>Upstream Sync</h3>
        <ul>
          <li>Use fork + scheduled sync workflow.</li>
          <li>Before merging, compare API routes and auth flow changes.</li>
          <li>After merging, run migration tests in local dev before deploy.</li>
        </ul>
      </section>
      <section className="card">
        <h3>Common Errors</h3>
        <ul>
          <li>401 Unauthorized: token expired, log in again.</li>
          <li>403 Account disabled: admin must unban your account.</li>
          <li>403 Invite invalid: invite expired or revoked.</li>
          <li>429 Too many requests: wait and retry.</li>
        </ul>
      </section>
    </div>
  );
}
