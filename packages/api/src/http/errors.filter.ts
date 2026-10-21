import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
import { ZodError } from 'zod';
import { AuthorizationError } from '../core/authorizationService';
import { LabPolicyError } from '../core/labPolicy';

/** Maps domain errors to HTTP codes so controllers can stay thin. */
@Catch()
export class DomainErrorFilter implements ExceptionFilter {
  catch(err: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse();
    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'internal error';

    if (err instanceof HttpException) {
      status = err.getStatus();
      message = err.message;
    } else if (err instanceof LabPolicyError || err instanceof AuthorizationError) {
      status = HttpStatus.FORBIDDEN;
      message = err.message;
    } else if (err instanceof ZodError) {
      status = HttpStatus.BAD_REQUEST;
      message = err.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    } else if (err instanceof Error) {
      // not-found style messages -> 404, otherwise 400 for known throws
      status = /not found/i.test(err.message) ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
      message = err.message;
    }
    res.status(status).send({ error: message, statusCode: status });
  }
}
