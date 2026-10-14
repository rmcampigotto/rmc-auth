import { Controller, Post, Body, Get, Ip, Headers, HttpCode } from '@nestjs/common';
import { AuthService, Public, Authorize, CurrentUser } from 'rmc-auth';
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
  async logout(@CurrentUser('id') userId: string) {
    await this.authService.logout(userId);
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
