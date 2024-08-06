import express from "express";
import { validate_admin_request } from "../pkg/request_rustler.js";
import he from "he";

const app = express();

app.use(express.json());

app.use((req, res, next) => {
  const origin = req.protocol + "://" + req.get("host");
  const url = origin + req.originalUrl;
  const result = validate_admin_request(
    {
      url,
      method: req.method,
      headers: req.headers,
    },
    {
      public_key: "123abc",
      private_key: "456def",
      origins: {
        app: `${origin}/app`,
        patch_session_token: `${origin}/app/patch`,
        login: `${origin}/app/login`,
        exit_iframe: `${origin}/app/exit`,
      },
    }
  );

  if (result.status) {
    const content = `
      <dl>
        <dt>status:</dt><dd>${result.status}</dd>
        <dt>body:</dt><dd>${he.encode(result.body)}</dd>
        <dt>headers:<dt><dd><pre>${he.encode(
          JSON.stringify(Object.fromEntries(result.headers), null, 2)
        )}</pre>
      </dl>
    `;

    res.send(content);
  }

  next();
});

const PORT = 3000;
app.listen(PORT, async () => {
  console.log(`Server is listening on port ${PORT}`);
});
