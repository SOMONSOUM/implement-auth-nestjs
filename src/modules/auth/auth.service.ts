import { Injectable, Logger } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { LoginInput } from './dto/input/login.input';
import * as bcrypt from 'bcrypt';
import { GraphQLError } from 'graphql';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from 'src/common/interfaces';
import { RefreshTokenInput } from './dto/input/refresh-token.input';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async refreshToken(input: RefreshTokenInput) {
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        input.refreshToken,
        {
          secret: this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET'),
        },
      );
      if (!payload) {
        throw new GraphQLError('Invalid refresh token', {
          extensions: {
            code: 'UNAUTHORIZED',
          },
        });
      }

      const accessToken = await this.jwtService.signAsync(
        { sub: payload.sub },
        {
          expiresIn: this.configService.getOrThrow<string>(
            'ACCESS_TOKEN_EXPIRATION',
          ),
          secret: this.configService.getOrThrow<string>('ACCESS_TOKEN_SECRET'),
        },
      );
      const refreshToken = await this.jwtService.signAsync(
        { sub: payload.sub },
        {
          expiresIn: this.configService.getOrThrow<string>(
            'REFRESH_TOKEN_EXPIRATION',
          ),
          secret: this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET'),
        },
      );
      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      if (error instanceof GraphQLError) {
        throw error;
      }
      if (error instanceof JsonWebTokenError) {
        throw new GraphQLError(error.message, {
          extensions: {
            code: error.name,
          },
        });
      } else {
        throw new GraphQLError(`Something went wrong`, {
          extensions: {
            code: 'INTERNAL_SERVER_ERROR',
          },
        });
      }
    }
  }

  async login(input: LoginInput) {
    const user = await this.userService.findOneByEmail(input.email);

    const isMatched = await bcrypt.compare(input.password, user.password);
    if (!isMatched) {
      throw new GraphQLError(`Password does not match the existing`, {
        extensions: {
          code: 'INCORRECT_PASSWORD',
        },
      });
    }

    const payload = { sub: user.id };

    const accessToken = await this.jwtService.signAsync(
      { sub: payload.sub },
      {
        expiresIn: this.configService.getOrThrow<string>(
          'ACCESS_TOKEN_EXPIRATION',
        ),
        secret: this.configService.getOrThrow<string>('ACCESS_TOKEN_SECRET'),
      },
    );
    const refreshToken = await this.jwtService.signAsync(
      { sub: payload.sub },
      {
        expiresIn: this.configService.getOrThrow<string>(
          'REFRESH_TOKEN_EXPIRATION',
        ),
        secret: this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET'),
      },
    );
    return {
      accessToken,
      refreshToken,
    };
  }
}
