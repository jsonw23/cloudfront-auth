import * as lambda from 'aws-cdk-lib/aws-lambda'
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs'
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager'
import * as s3 from 'aws-cdk-lib/aws-s3'
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront'
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as apigateway from 'aws-cdk-lib/aws-apigateway'

import { Construct } from 'constructs'
import { SecretValue, RemovalPolicy } from 'aws-cdk-lib'
import { StringParameter } from 'aws-cdk-lib/aws-ssm'
import { CachePolicy } from 'aws-cdk-lib/aws-cloudfront'

export interface CloudfrontAuthProps {
  oauthDomain: SecretValue
  oauthClientId: SecretValue
  oauthClientSecret: SecretValue
  jwtSecret: SecretValue
  refererToken: string
}

export class CloudfrontAuth extends Construct {

  bucket: s3.Bucket

  distribution: cloudfront.Distribution

  refererToken: string

  authEdge: lambda.Function

  constructor(scope: Construct, id: string, props: CloudfrontAuthProps) {
    super(scope, id);

    this.refererToken = props.refererToken

    const authEdge = new nodejs.NodejsFunction(this, 'auth', {
      runtime: lambda.Runtime.NODEJS_16_X,
      depsLockFilePath: 'yarn.lock'
    })
    this.authEdge = authEdge

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
      parameterName: `/cloudfront-auth/${authEdge.functionName}/secretArn`,
      stringValue: secret.secretFullArn!,
      simpleName: false
    })
    
    authEdge.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "ssm:DescribeParameters",
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:GetParametersByPath",
        ],
        resources: ['*']
      })
    )

    this.bucket = new s3.Bucket(this, 'AdminBucket', {
      removalPolicy: RemovalPolicy.DESTROY,
      websiteIndexDocument: 'index.html',
      websiteErrorDocument: 'index.html'
    })
    const grant = this.bucket.grantPublicAccess()
    grant.resourceStatement!.addCondition('StringEquals', {
      'aws:Referer': `CloudFront ${props.refererToken}`
    })

    this.distribution = new cloudfront.Distribution(this, 'cloudfrontDist', {
      defaultBehavior: {
        origin: new origins.S3Origin(this.bucket, {
          customHeaders: {
            Referer: `CloudFront ${props.refererToken}`
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

  addRestAPI = (path: string, restAPI: apigateway.RestApi) => {
    const origin = new origins.RestApiOrigin(restAPI, {
      customHeaders: {
        Referer: `CloudFront ${this.refererToken}`
      }
    })

    const apiPathFixer = lambda.Version.fromVersionArn(this, "apiPathFixer", "arn:aws:lambda:us-east-1:810588378601:function:CloudFrontApiPath:1")

    this.distribution.addBehavior(path, origin, {
      edgeLambdas: [
        {
          functionVersion: this.authEdge.currentVersion,
          eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST
        },
        {
          functionVersion: apiPathFixer,
          eventType: cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST
        }
      ],
      cachePolicy: CachePolicy.CACHING_DISABLED
    })
  }
}
