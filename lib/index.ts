// import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
// import * as sqs from 'aws-cdk-lib/aws-sqs';

export interface CloudfrontAuthProps {
  // Define construct properties here
}

export class CloudfrontAuth extends Construct {

  constructor(scope: Construct, id: string, props: CloudfrontAuthProps = {}) {
    super(scope, id);

    // Define construct contents here

    // example resource
    // const queue = new sqs.Queue(this, 'CloudfrontAuthQueue', {
    //   visibilityTimeout: cdk.Duration.seconds(300)
    // });
  }
}
