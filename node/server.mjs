import express from "express";
import { validate_admin_request } from "../pkg/request_rustler.js";
import he from "he";

const app = express();

app.use(express.json());

app.use((req, res, next) => {
  const origin = process.env.HOST;
  const request = {
    url: origin + req.originalUrl,
    method: req.method,
    headers: req.headers,
  };
  const options = {
    public_key: process.env.SHOPIFY_API_KEY,
    private_key: process.env.SHOPIFY_API_SECRET,
    origins: {
      app: `${origin}`,
      patch_session_token: `${origin}/patch`,
      login: `${origin}/login`,
      exit_iframe: `${origin}/exit`,
    },
  };

  const result = validate_admin_request(request, options);

  if (result.status) {
    const content = `
      <h2>Request</h2>
      <dl>
        <dt>request:</dt><dd><pre>${JSON.stringify(request, null, 2)}</pre></dd>
        <dt>options:</dt><dd><pre>${JSON.stringify(options, null, 2)}</pre></dd>
      </dl>
      <h2>Response</h2>
      <dl>
        <dt>status:</dt><dd>${result.status}</dd>
        <dt>body:</dt><dd>${he.encode(result.body)}</dd>
        <dt>headers:<dt><dd><pre>${he.encode(
          JSON.stringify(Object.fromEntries(result.headers), null, 2)
        )}</pre>
      </dl>
    `;

    res.send(content);
  } else {
    res.send(JSON.stringify(result));
  }

  next();
});

app.listen(process.env.PORT, async () => {
  console.log(`Server is listening on port ${process.env.PORT}`);
});
