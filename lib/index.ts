import * as lambda from 'aws-cdk-lib/aws-lambda'
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs'
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager'
import * as s3 from 'aws-cdk-lib/aws-s3'
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront'
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins'

import * as randomstring from "randomstring"

import { Construct } from 'constructs'
import { SecretValue, RemovalPolicy } from 'aws-cdk-lib'
import { StringParameter } from 'aws-cdk-lib/aws-ssm'
import { ProductStack } from 'aws-cdk-lib/aws-servicecatalog'

export interface CloudfrontAuthProps {
  oauthDomain: SecretValue
  oauthClientId: SecretValue
  oauthClientSecret: SecretValue
  jwtSecret: SecretValue
}

export class CloudfrontAuth extends Construct {

  bucket: s3.Bucket

  distribution: cloudfront.Distribution

  constructor(scope: Construct, id: string, props: CloudfrontAuthProps) {
    super(scope, id);

    const authEdge = new nodejs.NodejsFunction(this, 'auth', {
      runtime: lambda.Runtime.NODEJS_16_X,
      depsLockFilePath: 'yarn.lock'
    })

    const secret = new secretsmanager.Secret(this, 'secrets', {
      secretObjectValue: {
        OKTA_DOMAIN: props.oauthDomain,
        OKTA_OAUTH2_CLIENT_ID: props.oauthClientId,
        OKTA_OAUTH2_CLIENT_SECRET: props.oauthClientSecret,
        JWT_SECRET: props.jwtSecret
      }
    })
    secret.grantRead(authEdge.role!)

    const ssmParameter = new StringParameter(this, 'ssmSecretArn', {
      parameterName: `cloudfront-auth/${authEdge.functionName}/secretArn`,
      stringValue: secret.secretFullArn!
    })

    const refererToken = randomstring.generate(12)
    this.bucket = new s3.Bucket(this, 'AdminBucket', {
      removalPolicy: RemovalPolicy.DESTROY,
      websiteIndexDocument: 'index.html',
      websiteErrorDocument: 'index.html'
    })
    const grant = this.bucket.grantPublicAccess()
    grant.resourceStatement!.addCondition('StringEquals', {
      'aws:Referer': `CloudFront ${refererToken}`
    })

    this.distribution = new cloudfront.Distribution(this, 'cloudfrontDist', {
      defaultBehavior: {
        origin: new origins.S3Origin(this.bucket, {
          customHeaders: {
            Referer: `CloudFront ${refererToken}`
          }
        }),
        edgeLambdas: [
          {
            functionVersion: authEdge.currentVersion,
            eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST
          }
        ]
      }
    })
    
  }
}
