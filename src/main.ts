import { IncomingMessage, ServerResponse, createServer } from "http";
import url from "url";
import { Issuer, generators } from "openid-client";
import { config } from "./config";

const codeVerifier = generators.codeVerifier();
const codeChallenge = generators.codeChallenge(codeVerifier);

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
      post_logout_redirect_uris: [config.post_logout_redirect_uri],
      // id_token_signed_response_alg: "PS512",
    });

    const queryUrl = request.url;
    const myUrl = url.parse(<string>queryUrl);
    const searchParams = new URLSearchParams(<string>myUrl.query);
    const code = searchParams.get("code");

    if (!code) {
      // Get authorization code
      let authUrl = client.authorizationUrl({
        scope: config.scope,
        code_challenge: codeChallenge,
        response_types: config.response_type,
        redirect_uri: config.redirect_uri,
        code_challenge_method: "S256",
      });

      response.writeHead(301, {
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
