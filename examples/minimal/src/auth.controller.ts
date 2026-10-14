import { Controller, Post, Body, Get, Ip, Headers, HttpCode } from '@nestjs/common';
import { AuthService, Public, Authorize, CurrentUser, AccessToken } from 'rmc-auth';
import type { RequestUser } from 'rmc-auth';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  async login(
    @Body() body: { email: string; password: string },
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.authService.login(body, { ip, userAgent });
  }

  @Public()
  @Post('refresh')
  async refresh(@Body('refreshToken') refreshToken: string, @Ip() ip: string) {
    return this.authService.refresh(refreshToken, { ip });
  }

  @Post('logout')
  @HttpCode(204)
  async logout(@CurrentUser('id') userId: string, @AccessToken() token: string) {
    await this.authService.logout(userId, undefined, token);
  }

  @Post('change-password')
  @HttpCode(204)
  async changePassword(
    @CurrentUser('id') userId: string,
    @Body() body: { currentPassword: string; newPassword: string },
  ) {
    await this.authService.changePassword(userId, body.currentPassword, body.newPassword);
  }

  @Public()
  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    const reset = await this.authService.createPasswordResetToken(email);
    // In a real app, e-mail the token instead of logging it.
    if (reset) console.log(`Password reset token for ${email}: ${reset.token}`);
    return { message: 'If the account exists, an e-mail was sent.' };
  }

  @Public()
  @Post('reset-password')
  @HttpCode(204)
  async resetPassword(@Body() body: { token: string; password: string }) {
    await this.authService.resetPassword(body.token, body.password);
  }
}

@Controller('profile')
export class ProfileController {
  @Get()
  @Authorize('user')
  getProfile(@CurrentUser() user: RequestUser) {
    return { id: user.id, username: user.username, roles: user.roles };
  }
}
