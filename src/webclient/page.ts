import { LIMITS } from '../config/limits';
import { renderWebClientScript } from './script';
import { WEB_CLIENT_STYLES } from './styles';

export function renderWebClientHTML(): string {
  const defaultKdfIterations = LIMITS.auth.defaultKdfIterations;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NodeWarden Web</title>
  <style>
${WEB_CLIENT_STYLES}
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
${renderWebClientScript(defaultKdfIterations)}
  </script>
</body>
</html>`;
}
