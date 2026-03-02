import { Controller, Post, Body, Get, UseGuards, Request } from '@nestjs/common';
import { AuthService, Public, Authorize } from 'rmc-auth';
import type { RequestUser } from 'rmc-auth';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body);
  }

  @Public()
  @Post('refresh')
  async refresh(@Body('refreshToken') refreshToken: string) {
    return this.authService.refresh(refreshToken);
  }
}

@Controller('profile')
export class ProfileController {
  @Get()
  @Authorize('user')
  getProfile(@Request() req: { user: RequestUser }) {
    return { id: req.user.id, username: req.user.username, roles: req.user.roles };
  }
}
