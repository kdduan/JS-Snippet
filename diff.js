const pemEncodedKey =
  "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9ocLD8ukY9sAM6MMsvWbJz0pgFsVNHKZrIvqkGDb8xbsJuFjogKsg6X3FLzXB+nVQWiHZMcJpyOv74+U3FFEx0Nci15ZCISW1pFWzvK2M4XvMx7z89GXVgCJXzy1gU78xR/NumQ8l6LEibyqW0keFIYKINC+/SgQFevE22R3MQyiduNcY93vYBCeXhY2dvH1i/57rDxT8NvtR\nBEM/uItRRyn7gLlI7jioJItaPv/iBJhFl0OxKcqXAFtIV9450NuVAvHaS1JPLTvoV8s6s3SsZnZ00ImU+wR4fpuiZ+NWZYkPzaiWBzqTz8KuzO+ntkYLsrWcovtxsjFSJU4+YzYtAgMBAAECggEAEoL/CLKRhL6vGCjaHLz56CDUlDVvhKE+XF5pdKlp0hqEsWSN8VcriCajAM56A09YMm7fYlzUK2V80UskWNB37f1YHcOenHgF6V8l1UpJmuN20BJ+OtH/kEGrmJeAnihZarh+ZWvgVFq3KAhix58MHPfyI9UMWt0hMAkaEQ5NirSnS5gTaYk/eKBDWTVx6ABanFnvu+6UOd3ADbcgLVApDhswOHKRj7h/fkcD1OcVrVG4seiKnemBO60OTi3NK5XU6dCp43wx6Vj0OPYUFYGDfNYVhg5s21aU8IO671jQMQL2+YuRL9knTBMyRZQx7bykOBSuiR+zmEdBtAwO3Ka5dQKBgQDenEiEvAgxTARnGK/TjDLoRbwqg4A4e1ZFrWspAvXlMTvkWopDXjskfHTlIH46gwYjFaf3Hx40l2WDjMrKOlFG/rlDsWo+BYUjk5OwknSXCiFSJQUHMcJMhd/RGzL3pWerQ5a7kaJU5Kl3nxJ+KfAcVcO5oGUxO/+q6lHvTghDewKBgQDaEy1S3z/Jc5ZhlrEb33trZBFCeLmhb/qupQE2H5AYhCaaKt/yBGLym35EVwHMVK5SQYge16Ob35TlBXr9qvKMjupWYAQW6C+8KuYTH9oYj7UFhYKKHq+JlI8nc8h1p8TK9QVmBJt1O+ocWMNOZrdYkMb8LgllNreN47UA4FAIdwKBgQDFEFSiLFKUUVcUbSY5f8MRG6qXeBHp7kVRKVPT2msTmaILZJtBSAnTItnYfAtCgPrN1D385e83X07eRaS/oSCSWKxo4IXModZayCnWBdBwZOdacKsi00nNtDWORyW3VRWQ5yRop2OtAz+CRa95QGburn21tefezd5mz0f5MHrgQQKBgDe48rncRcZJ/MEO6k5++mBkf2yGwJgZrup1SyvzQLSi/+Ig1nxW1pm7VbZMrS7y7GAkUo3e9/VaWgdzMQwkZDm6QvKzMhhQV/Iy2/tDBk2EWvMAPGzijmQPS8z+7tfxeH2LwkdhIgAAwT9hBva/lFXTGKVTdh8griJZbuS8bHbdAoGAXXRisuE3hfLYGkueNlWZxGjcEJ0HHwqJa7i4aaOwuFv/0RwDrfqp21ojvVKnX0LQ0Eb+oZ+1rwolSmsR4xfl//01MKq8rDPNSmgFZ1QtUE1f2O0H6Bsi/AvqsqUHrdUyzplNLlRRhCMeFS48zkKgYWamG42aTdfJUzdOkUMxUJ8=-----END PRIVATE KEY-----";
const spreadsheetID = "1AOzMA60xYUxHI37kE5HOdUvuSchPK-_arOAj7IiICTQ";

/**
 * Convert a string into an ArrayBuffer from
 * https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
 */
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/**
 * Import a PEM encoded RSA private key, to use for RSA-PSS signing.
 * Takes a string containing the PEM encoded key, and returns a Promise
 * that will resolve to a CryptoKey representing the private key.
 * Reference PKCS #8 import at
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#Examples
 */
function importPrivateKey(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(
    pemHeader.length,
    pem.length - pemFooter.length
  );

  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);

  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign"]
  );
}

/**
 * Generates a digital signature for the JWT
 * @param  pem           PEM-encoded private key for the Service Account
 * @param  input         data to be signed (JWT header + claim set)
 * @return               Promise which will be fulfilled with the signature
 * Reference SubtleCrypto.sign() at
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
 */
async function getSignature(pem, input) {
  privateKey = await importPrivateKey(pem);
  const enc = new TextEncoder();
  const encodedMessage = enc.encode(input);
  const signature = await window.crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    encodedMessage
  );
  return signature;
}

/**
 * Gets an OAuth2 access token to authenticate Google Sheets API usage
 * @param  pem           PEM-encoded private key for the service account
 * @return               access token
 * Reference this guide:
 * https://developers.google.com/identity/protocols/oauth2/service-account
 */
async function getToken(pem) {
  //form the JWT header
  var header = { alg: "RS256", typ: "JWT" };

  // form the claim set
  var claims = {
    iss: "diffbot@enhanceip.iam.gserviceaccount.com",
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token",
    exp: Math.round(Date.now() / 1000) + 3600,
    iat: Math.round(Date.now() / 1000),
  };

  // base64url-encode the header & claim set
  const input =
    btoa(JSON.stringify(header)) + "." + btoa(JSON.stringify(claims));

  // sign the above input using the service account's private key
  const byteArray = await getSignature(pem, input);

  // base64url-encode the signature byte array
  const signature = btoa(
    Array.from(new Uint8Array(byteArray))
      .map((val) => {
        return String.fromCharCode(val);
      })
      .join("")
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/\=/g, "");

  // construct the final JWT
  const jwt = input + "." + signature;

  // send a request to get an access token
  const tokenRes = await fetch(`https://oauth2.googleapis.com/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Host: "oauth2.googleapis.com",
    },
    body: JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  const tokenJson = await tokenRes.json();
  return tokenJson["access_token"];
}

/**
 * Gets data from client's IP address and writes to Google Sheets
 * https://docs.google.com/spreadsheets/d/1AOzMA60xYUxHI37kE5HOdUvuSchPK-_arOAj7IiICTQ/edit?usp=sharing
 * @param  pem           PEM-encoded private key for the service account
 */
async function main(pem) {
  // get basic geolocation data from IP address
  const ipRes = await fetch("http://ip-api.com/json/?fields=17035263");
  const ipData = await ipRes.json();

  // get enhanced data from IP address via DiffBot
  const params = {
    token: "ba9bef12e8ed1656418df54db3c98bb8",
    ip: ipData["query"],
    size: 1,
    threshold: 0.25,
  };
  var diffRes = await fetch(
    "https://kg.diffbot.com/kg/v3/enhance_endpoint?" +
      new URLSearchParams(params)
  );
  const diffJson = await diffRes.json();
  const enhanceData = diffJson["data"];

  // extract IP data fields
  var IP = ipData["query"];
  var ISP = ipData["isp"];
  var Proxy = ipData["proxy"].toString();
  var Hosting = ipData["hosting"].toString();
  var IP_City = ipData["city"];
  var IP_Region = ipData["regionName"];
  var IP_Country = ipData["countryCode"];
  var IP_LatLong = ipData["lat"] + "," + ipData["lon"];
  var IP_Postal = ipData["zip"];
  var IP_Timezone = ipData["timezone"];

  // initialize Diffbot data to empty strings
  var DiffbotID = "";
  var Name = "";
  var Homepage = "";
  var Description = "";
  var Logo = "";
  var Employees = "";
  var Address = "";
  var Industries = "";
  var DiffbotFound = "FALSE";

  // update with Diffbot data if found
  if (enhanceData.length !== 0) {
    DiffbotID = enhanceData[0]["entity"]["id"];
    Name = enhanceData[0]["entity"]["name"];
    Homepage = enhanceData[0]["entity"]["homepageUri"];
    Description = enhanceData[0]["entity"]["description"];
    Logo = enhanceData[0]["entity"]["logo"];
    Employees =
      enhanceData[0]["entity"]["nbEmployeesMin"] +
      "-" +
      enhanceData[0]["entity"]["nbEmployeesMax"];
    Address = enhanceData[0]["entity"]["location"]["address"];
    Industries = JSON.stringify(enhanceData[0]["entity"]["industries"]);
    DiffbotFound = "TRUE";
  }

  // get Google Sheets API access token
  const accessToken = await getToken(pemEncodedKey);

  // get client's current URL
  const currUrl = window.location.href;

  // use the Sheets API to add a row containing data extracted from IP address
  await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetID}:batchUpdate`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        requests: [
          {
            appendCells: {
              sheetId: 0,
              rows: [
                {
                  values: [
                    { userEnteredValue: { stringValue: IP } },
                    { userEnteredValue: { stringValue: currUrl } },
                    { userEnteredValue: { stringValue: ISP } },
                    { userEnteredValue: { stringValue: Proxy } },
                    { userEnteredValue: { stringValue: Hosting } },
                    { userEnteredValue: { stringValue: IP_City } },
                    { userEnteredValue: { stringValue: IP_Region } },
                    { userEnteredValue: { stringValue: IP_Country } },
                    { userEnteredValue: { stringValue: IP_LatLong } },
                    { userEnteredValue: { stringValue: IP_Postal } },
                    { userEnteredValue: { stringValue: IP_Timezone } },
                    { userEnteredValue: { stringValue: DiffbotID } },
                    { userEnteredValue: { stringValue: Name } },
                    { userEnteredValue: { stringValue: Homepage } },
                    { userEnteredValue: { stringValue: Description } },
                    { userEnteredValue: { stringValue: Logo } },
                    { userEnteredValue: { stringValue: Employees } },
                    { userEnteredValue: { stringValue: Address } },
                    { userEnteredValue: { stringValue: Industries } },
                    { userEnteredValue: { stringValue: DiffbotFound } },
                  ],
                },
              ],
              fields: "*",
            },
          },
        ],
      }),
    }
  );
}

$(document).ready(main());
