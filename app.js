require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
var cors = require("cors");
var cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require('uuid');
const crypto = require("crypto");
const fetch = require("node-fetch")
const OAuth = require('oauth-1.0a')
const oauthSignature = require("oauth-signature")

const app = express();
const port = 8080;

app.use(cors());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

let OAUTH_VERIFIER = ""
let REQUEST_TOKEN = ""
let REQUEST_TOKEN_SECRET = ""
let ACCESS_TOKEN = ""
let ACCESS_TOKEN_SECRET = ""

app.post("/activate-callback", (req, res) => {
  OAUTH_VERIFIER = req.body.oauth_verifier
  console.log("activate callback: ", req.body);
  res.status(200).send();
});

app.get("/request-token", async (req, resp) => {
  const oauth = new OAuth({
    consumer: { key: process.env.CONSUMER_KEY, secret: process.env.CONSUMER_SECRET },
    signature_method: 'HMAC-SHA1',
    hash_function(base_string, key) {
        return crypto
            .createHmac('sha1', key)
            .update(base_string)
            .digest('base64')
    },
})

const request_data = {
  url: process.env.MAGENTO_STORE_URL+'/oauth/token/request',
  method: 'POST',
  data: { },
}
const authHeader = oauth.toHeader(oauth.authorize(request_data))

try{
  const response = await fetch(request_data.url,{
    method: request_data.method,
    headers: {
      'Authorization': authHeader["Authorization"],
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  })
  const req_tokens_str = await response.text()
  const params = new URLSearchParams(req_tokens_str)
  REQUEST_TOKEN = params.get("oauth_token")
  REQUEST_TOKEN_SECRET = params.get("oauth_token_secret")
  console.log(req_tokens_str)
  resp.status(200).send({REQUEST_TOKEN,REQUEST_TOKEN_SECRET})
}
catch(err){
  resp.status(400).send(err)
}
});

app.get("/access-token", (req, resp) => {
  const timestamp = new Date().getTime() / 1000
  const nonce = uuidv4()
  const url = process.env.MAGENTO_STORE_URL+"/oauth/token/access"
  const signatureParams = {
    oauth_consumer_key : process.env.CONSUMER_KEY,
    oauth_token : REQUEST_TOKEN,
    oauth_nonce : nonce,
    oauth_timestamp :  timestamp,
    oauth_signature_method : 'HMAC-SHA1',
    oauth_version : '1.0',
    oauth_verifier: OAUTH_VERIFIER
  }
  const signature = oauthSignature.generate('POST', url, signatureParams, process.env.CONSUMER_SECRET, REQUEST_TOKEN_SECRET)

  fetch(url, {
    method: "POST",
    headers: {
      'Authorization': `OAuth oauth_consumer_key="${process.env.CONSUMER_KEY}",oauth_signature_method="HMAC-SHA1",oauth_timestamp="${timestamp}",oauth_nonce="${nonce}",oauth_version="1.0",oauth_signature="${signature}",oauth_token="${REQUEST_TOKEN}",oauth_verifier="${OAUTH_VERIFIER}"`,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  })
    .then((res) => {
        console.log(res)
        return res.text()
    }) 
    .then((token_res) => {
        const params = new URLSearchParams(token_res)
        const ACCESS_TOKEN = params.get("oauth_token")
        const ACCESS_TOKEN_SECRET = params.get("oauth_token_secret")
        console.log(token_res)
        resp.status(200).send({ACCESS_TOKEN,ACCESS_TOKEN_SECRET})
    });
});

app.get("/products", (req, resp) => {
  const oauth = new OAuth({
    consumer: { key: process.env.CONSUMER_KEY, secret: process.env.CONSUMER_SECRET },
    signature_method: 'HMAC-SHA1',
    hash_function(base_string, key) {
        return crypto
            .createHmac('sha1', key)
            .update(base_string)
            .digest('base64')
    },
  })

  const request_data = {
    url: process.env.MAGENTO_STORE_URL+"/rest/default/V1/categories/list",
    method: 'GET',
    data: {}
  }

  const token = {
    key: ACCESS_TOKEN,
    secret: ACCESS_TOKEN_SECRET
  }
  const authHeader = oauth.toHeader(oauth.authorize(request_data,token))
  fetch(process.env.MAGENTO_STORE_URL+"/rest/default/V1/categories/list", {
    method: "GET",
    headers: {
      'Authorization': authHeader["Authorization"],
      'Content-Type': 'application/json',
      'Accept': 'application/json' 
    }
  })
    .then((res) => {
        console.log(res)
        res.json()
    }) // expecting a json response
    .then((json) => {
        console.log(json)
        resp.status(200).send(json)
    });
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Magento OAuth Sample App listening at http://localhost:${port}`);
});
