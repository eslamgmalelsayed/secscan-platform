import { S3Client, GetPublicAccessBlockCommand } from '@aws-sdk/client-s3';
const [Bucket] = process.argv.slice(2);
if (!Bucket) throw new Error('Supply one bucket name');
try {
  const { PublicAccessBlockConfiguration } = await new S3Client({}).send(
    new GetPublicAccessBlockCommand({ Bucket }),
  );
  console.log(JSON.stringify({ Bucket, at: new Date().toISOString(), PublicAccessBlockConfiguration }));
} catch (e) {
  console.error('Bucket configuration unavailable: ' + e.name);
  process.exitCode = 1;
}
