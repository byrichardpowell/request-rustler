import express from "express";
import { validate_admin_request } from "./pkg/request_rustler.js";

const app = express();

app.use(express.json());

app.use((req, res, next) => {
  const result = validate_admin_request(
    {
      url: process.env.HOST + req.originalUrl,
      method: req.method,
      headers: req.headers,
    },
    {
      public_key: process.env.SHOPIFY_API_KEY,
      private_key: process.env.SHOPIFY_API_SECRET,
      urls: {
        app: `${process.env.HOST}`,
        patch_session_token: `${process.env.HOST}/patch`,
        login: `${process.env.HOST}/login`,
        exit_iframe: `${process.env.HOST}/exit`,
      },
    }
  );

  if (result.status) {
    // Request was not OK
    // Send Response suggested by validate_admin_request()
    const { status, body, headers } = result;
    res.status(status).set(headers).send(body);
  } else {
    // Request was OK
    // Send the id_token and payload returned from validate_admin_request()
    // Here a real app might do token exchange or fetch data etc instead
    res.send(JSON.stringify(result));
  }

  next();
});

app.listen(process.env.PORT, async () => {
  console.log(`Server is listening on port ${process.env.PORT}`);
});
