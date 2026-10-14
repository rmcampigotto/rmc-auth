import { HttpException, HttpStatus } from "@nestjs/common";

/**
 * Thrown by `login()` when the password is correct but the user has two-factor authentication enabled.
 * Responds 401 with `{ statusCode, message, mfaRequired: true, mfaToken, expiresIn }`.
 * The client then calls the endpoint that runs `verifyTwoFactorLogin(mfaToken, code)`.
 */
export class TwoFactorRequiredException extends HttpException {
  constructor(
    public readonly mfaToken: string,
    public readonly expiresIn: number
  ) {
    super(
      {
        statusCode: HttpStatus.UNAUTHORIZED,
        message: "Two-factor authentication required",
        mfaRequired: true,
        mfaToken,
        expiresIn,
      },
      HttpStatus.UNAUTHORIZED
    );
  }
}
