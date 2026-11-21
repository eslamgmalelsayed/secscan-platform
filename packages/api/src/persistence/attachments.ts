import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createHash } from 'node:crypto';

export interface AttachmentStore {
  put(project: string, text: string): Promise<string>;
  read(project: string, id: string): Promise<{ url: string }>;
}
/** Only redacted text evidence can enter this private bucket through the API. */
export function s3Attachments(env: NodeJS.ProcessEnv = process.env): AttachmentStore | undefined {
  const Bucket = env.SECSCAN_EVIDENCE_BUCKET;
  if (!Bucket) return undefined;
  const client = new S3Client({
    region: env.AWS_REGION || 'us-east-1',
    endpoint: env.SECSCAN_S3_ENDPOINT || undefined,
    forcePathStyle: !!env.SECSCAN_S3_ENDPOINT,
  });
  const key = (project: string, id: string) => 'assessment-evidence/' + project + '/' + id + '.txt';
  return {
    async put(project, text) {
      const id = createHash('sha256').update(text).digest('hex');
      await client.send(
        new PutObjectCommand({
          Bucket,
          Key: key(project, id),
          Body: text,
          ContentType: 'text/plain; charset=utf-8',
          ServerSideEncryption: 'AES256',
        }),
      );
      return id;
    },
    async read(project, id) {
      return {
        url: await getSignedUrl(
          client,
          new GetObjectCommand({
            Bucket,
            Key: key(project, id),
            ResponseContentDisposition: 'attachment; filename="evidence.txt"',
          }),
          { expiresIn: 60 },
        ),
      };
    },
  };
}
