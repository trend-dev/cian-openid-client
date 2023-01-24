import { IncomingMessage, ServerResponse, createServer } from "http";
import url from "url";
import { Issuer, generators } from "openid-client";
import { config } from "./config";

if (!config.authority)
  throw "No config file found! Just create config.ts file from example.config.ts";
const code_verifier = generators.codeVerifier();
const code_challenge = generators.codeChallenge(code_verifier);

const PORT = 4200;

async function requestHandler(
  request: IncomingMessage,
  response: ServerResponse
) {
  try {
    // Authorize issuer - get meatadata from open ID server
    const cianIssuer = await Issuer.discover(config.authority);

    const client = new cianIssuer.Client({
      client_id: config.client_id,
      client_secret: config.client_secret,
      redirect_uris: [config.redirect_uri],
      response_types: [config.response_type],
      // id_token_signed_response_alg: "PS512",
    });

    const queryUrl = <string>request.url;
    const myUrl = url.parse(queryUrl);
    const searchParams = new URLSearchParams(<string>myUrl.query);
    const code = searchParams.get("code");

    if (!code) {
      // Get authorization code
      let authUrl = client.authorizationUrl({
        scope: config.scope,
        code_challenge: code_challenge,
        response_types: config.response_type,
        redirect_uri: config.redirect_uri,
        code_challenge_method: "S256",
      });

      response.writeHead(302, {
        Location: authUrl,
      });
      response.end();
    } else {
      // Exchange code with access token and refresh token
      const params = client.callbackParams(request);

      let tokenSet = await client.callback(config.redirect_uri, params);
      console.log("received and validated tokens %j", tokenSet);
      console.log("validated ID Token claims %j", tokenSet.claims());

      response.writeHead(200);
      //   let json = JSON.stringify(userinfo);
      response.end();
    }
  } catch (err) {
    console.error(err);
    response.end();
  }
}

const server = createServer(requestHandler);

server.listen(PORT, () => {
  console.log(`OpenID client is running on ${PORT}`);
});
