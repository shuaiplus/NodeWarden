import type { ComponentChildren } from 'preact';

interface StandalonePageFrameProps {
  title: string;
  children: ComponentChildren;
}

export default function StandalonePageFrame(props: StandalonePageFrameProps) {
  return (
    <div className="standalone-shell">
      <div className="standalone-brand standalone-brand-outside">
        <img src="/logo-64.png" alt="NodeWarden logo" className="standalone-brand-logo" />
        <div>
          <div className="standalone-brand-title">NodeWarden</div>
        </div>
      </div>

      <div className="auth-card">
        <h1 className="standalone-title">{props.title}</h1>
        {props.children}
      </div>

      <div className="standalone-footer">
        <a href="https://github.com/shuaiplus/NodeWarden" target="_blank" rel="noreferrer">NodeWarden Repository</a>
        <span> | </span>
        <a href="https://github.com/shuaiplus" target="_blank" rel="noreferrer">Author: @shuaiplus</a>
      </div>
    </div>
  );
}
