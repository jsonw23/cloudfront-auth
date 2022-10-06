import * as cookie from "cookie"
import * as jwt from "jsonwebtoken"
import * as randomstring from "randomstring"
import * as crypto from "crypto"
import * as https from "https"
import base64url from "base64url"
import { URLSearchParams } from "url"

import { SecretsManagerClient, GetSecretValueCommand, GetSecretValueCommandInput } from "@aws-sdk/client-secrets-manager"
import { SSMClient, GetParameterCommand, GetParameterCommandInput } from "@aws-sdk/client-ssm"

import { 
    CloudFrontRequestEvent,
    CloudFrontRequestResult,
    CloudFrontHeaders, 
    CloudFrontRequestCallback, 
    Context } from "aws-lambda"

interface JwtPayloadAuthRedirect {
    code_verifier: string
    state: string
}

interface JwtPayloadAuthenticated {
    access_token: string
    id_token: string
}

interface Secrets {
    OKTA_DOMAIN?: string
    OKTA_OAUTH2_CLIENT_ID?: string
    OKTA_OAUTH2_CLIENT_SECRET?: string
    JWT_SECRET?: string
}

const secretClient = new SecretsManagerClient({ region: 'us-east-1' })
let secrets: Secrets = {
    OKTA_DOMAIN: undefined,
    OKTA_OAUTH2_CLIENT_ID: undefined,
    OKTA_OAUTH2_CLIENT_SECRET: undefined,
    JWT_SECRET: undefined,
}

const AUTH_CALLBACK = "/authorization-code/callback"

const UNAUTHORIZED_RESPONSE = {
    status: '401',
    headers: {
        'content-type': [
            {
                key: 'Content-Type',
                value: 'text/html'
            }
        ],
        'cache-control': [
            {
                key: 'Cache-Control',
                value: 'private'
            }
        ]
    },
    body: '<html><head><title>Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>'
}

const AUTH_REDIRECT: CloudFrontRequestResult = {
    status: '302',
    statusDescription: 'Found',
    headers: {
        location: [
            {
                key: 'Location',
                value: ''
            }
        ],
        'cache-control': [
            {
                key: 'Cache-Control',
                value: 'private'
            }
        ],
        'set-cookie': [
            {
                key: 'Set-Cookie',
                value: ''
            }
        ]
    }
}

const AUTH_SUCCESSFUL: CloudFrontRequestResult = {
    status: '302',
    headers: {
        location: [
            {
                key: 'Location',
                value: '/index.html'
            }
        ],
        'cache-control': [
            {
                key: 'Cache-Control',
                value: 'private'
            }
        ],
        'set-cookie': [
            {
                key: 'Set-Cookie',
                value: ''
            }
        ]
    }
}

function generateAuthRedirect(host: string) {
    const response = AUTH_REDIRECT!

    const state = randomstring.generate(64)
    const code_verifier = randomstring.generate(64)

    response!.headers!["set-cookie"][0].value = `auth=${jwt.sign({ state, code_verifier }, secrets.JWT_SECRET!)}; Secure; HttpOnly; SameSite=Lax; Path=/`

    const base64Digest = crypto
        .createHash("sha256")
        .update(code_verifier)
        .digest("base64")

    const code_challenge = base64url.fromBase64(base64Digest)

    const urlParams = new URLSearchParams()
    urlParams.set('client_id', secrets.OKTA_OAUTH2_CLIENT_ID!)
    urlParams.set('redirect_uri', `https://${host}${AUTH_CALLBACK}`)
    urlParams.set('scope', 'openid email profile')
    urlParams.set('state', state)
    urlParams.set('code_challenge', code_challenge)
    urlParams.set('code_challenge_method', 'S256')
    urlParams.set('response_type', 'code')
    urlParams.set('response_mode', 'query')

    response.headers!.location[0].value = `https://${secrets.OKTA_DOMAIN!}/oauth2/default/v1/authorize?${urlParams}`

    return response
}

interface OktaTokens {
    idToken?: string
    accessToken?: string
}

async function getOktaTokens(authCode: string, jwt: JwtPayloadAuthRedirect, host: string): Promise<OktaTokens|null> {
    const payload = new URLSearchParams()
    payload.set('grant_type', 'authorization_code')
    payload.set('redirect_uri', `https://${host}${AUTH_CALLBACK}`)
    payload.set('code', authCode)
    payload.set('code_verifier', jwt.code_verifier)

    return new Promise((resolve, _) => {
        const req = https.request({
            method: 'POST',
            hostname: secrets.OKTA_DOMAIN,
            path: '/oauth2/default/v1/token',
            auth: `${secrets.OKTA_OAUTH2_CLIENT_ID}:${secrets.OKTA_OAUTH2_CLIENT_SECRET}`,
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        }, res => {
            if (res.statusCode === 200) {
                let rawData = ''

                res.on('data', chunk => rawData += chunk)

                res.on('end', () => {
                    const jsonResponse = JSON.parse(rawData)

                    if ('scope' in jsonResponse && jsonResponse.scope.includes('openid') &&
                            'id_token' in jsonResponse) {
                        resolve({ 
                            idToken: jsonResponse.id_token,
                            accessToken: jsonResponse.access_token
                        })
                    } else {
                        resolve(null)
                    }
                })
            } else {
                console.error(`token exchange failed with status: ${res.statusCode}`)
                res.resume()
                resolve(null)
            }
        })

        req.on('error', error => {
            console.error(error)
            resolve(null)
        })

        req.write(payload.toString())
        req.end()
    })
}

function generateAuthSuccess(oktaTokens: OktaTokens) {
    const response = AUTH_SUCCESSFUL!

    response!.headers!["set-cookie"][0].value = generateAuthCookie(oktaTokens!)

    return response
}

function generateAuthCookie(oktaTokens: OktaTokens) {
    const payload: JwtPayloadAuthenticated = {
        id_token: oktaTokens.idToken!,
        access_token: oktaTokens.accessToken!
    }

    const signedJwt = jwt.sign(payload, secrets.JWT_SECRET!, {
        expiresIn: 3600
    })

    return `auth=${signedJwt}; Secure; HttpOnly; SameSite=Lax; Path=/`
}

function getAuth(requestHeaders: CloudFrontHeaders): JwtPayloadAuthRedirect | JwtPayloadAuthenticated | null {
    if (requestHeaders.cookie) {
        for (let i = 0; i < requestHeaders.cookie.length; i++) {
            const cookies = cookie.parse(requestHeaders.cookie[i].value)

            if ('auth' in cookies) {
                const signedJwt = cookies['auth']

                try {
                    const decodedJwt = jwt.verify(signedJwt, secrets.JWT_SECRET!)
                    console.log(decodedJwt)
                    return decodedJwt as JwtPayloadAuthRedirect | JwtPayloadAuthenticated
                } catch (err) {
                    console.warn(`JWT verification error: ${err}`)
                }
            }
        }
    }
    console.log("no auth cookie present")

    return null
}

exports.handler = async (event: CloudFrontRequestEvent, context: Context, callback: CloudFrontRequestCallback) => {
    const request = event.Records[0].cf.request
    const headers = request.headers
    const host = headers.host[0].value
    const queryParams = new URLSearchParams(request.querystring)

    // load the secrets in if they aren't there yet
    if (secrets.OKTA_DOMAIN === undefined) {
        const ssmClient = new SSMClient({
            region: "us-east-1"
        });
        const ssmOutput = await ssmClient.send(new GetParameterCommand({
            Name: `cloudfront-auth/${context.functionName}/secretArn`
        }))
        const secretArn = ssmOutput.Parameter!.Value
        const result = await secretClient.send(new GetSecretValueCommand({
            SecretId: secretArn
        }))
        secrets = JSON.parse(result.SecretString!)
    }

    // first check for an auth cookie
    const verifiedJwt = getAuth(headers)
    
    if (verifiedJwt && 'access_token' in verifiedJwt && request.uri !== AUTH_CALLBACK) {
        console.log("auth succeeded, forwarding to origin")
        callback(null, request)
    } else if (verifiedJwt && 'code_verifier' in verifiedJwt && request.uri === AUTH_CALLBACK) {
        console.log("auth callback, excange code for token")
        if (queryParams.has('code')) {
            // check state
            if (queryParams.get('state') !== verifiedJwt.state) {
                // state mismatch
                callback(null, UNAUTHORIZED_RESPONSE)
            }

            // okta callback, exchange code for tokens
            const oktaTokens = await getOktaTokens(queryParams.get('code')!, verifiedJwt, host)

            if (oktaTokens !== null) {
                callback(null, generateAuthSuccess(oktaTokens))
            } else {
                callback(null, UNAUTHORIZED_RESPONSE)
            }
        } else {
            // not an okta callback, redirect to login
            callback(null, generateAuthRedirect(host))
        }
    } else {
        console.log("redirect for auth")
        // not authorized yet
        callback(null, generateAuthRedirect(host))
    }
}