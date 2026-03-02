import { Injectable, OnModuleInit } from '@nestjs/common';
import { IAuthUserService, EncryptionService } from 'rmc-auth';

interface User {
  id: string;
  email: string;
  password: string;
  roles: string[];
  refreshToken?: string | null;
}

@Injectable()
export class UsersService implements IAuthUserService, OnModuleInit {
  private readonly users: Map<string, User> = new Map();

  constructor(private readonly encryption: EncryptionService) {}

  async onModuleInit(): Promise<void> {
    const hashed = await this.encryption.hash('Password123!');
    this.users.set('user@example.com', {
      id: '1',
      email: 'user@example.com',
      password: hashed,
      roles: ['user'],
    });
  }

  async findOneByField(field: string, value: unknown): Promise<User | null> {
    if (field === 'email') {
      const u = this.users.get(String(value));
      return u ?? null;
    }
    if (field === 'id') {
      for (const u of this.users.values()) {
        if (u.id === value) return u;
      }
    }
    return null;
  }

  async saveRefreshToken(userId: string, token: string): Promise<void> {
    for (const u of this.users.values()) {
      if (u.id === userId) {
        u.refreshToken = token;
        return;
      }
    }
  }

  async isRefreshTokenValid(userId: string, token: string): Promise<boolean> {
    for (const u of this.users.values()) {
      if (u.id === userId) return u.refreshToken === token;
    }
    return false;
  }

  async revokeAllTokens(userId: string): Promise<void> {
    for (const u of this.users.values()) {
      if (u.id === userId) {
        u.refreshToken = null;
        return;
      }
    }
  }

}
