import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { GraphQLError } from 'graphql';
import { JwtPayload } from 'src/common/interfaces';
import { UserService } from 'src/modules/user/user.service';
import { IS_PUBLICE_KEY } from '../decorators';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly reflector: Reflector,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    let request: Request;
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLICE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    if (context.getType() === 'http') {
      request = context.switchToHttp().getRequest();
    } else {
      request = this.getGqlRequest(context);
    }
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new GraphQLError(`Please provide token!`, {
        extensions: {
          code: 'UNAUTHENTICATED',
        },
      });
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: this.configService.getOrThrow<string>('JWT_SECRET_KEY'),
      });

      const user = await this.userService.findOneById(payload.sub);

      if (!user) {
        throw new GraphQLError(`Invalid token`, {
          extensions: {
            code: 'UNAUTHENTICATED',
          },
        });
      }
      request['user'] = user;
    } catch (error) {
      this.logger.error(error);
      if (error instanceof JsonWebTokenError) {
        throw new GraphQLError(error.message, {
          extensions: {
            code: 'UNAUTHENTICATED',
          },
        });
      } else if (error instanceof GraphQLError) {
        throw error;
      } else {
        throw new GraphQLError(`You are not authenticated`, {
          extensions: {
            code: 'UNAUTHENTICATED',
          },
        });
      }
    }

    return true;
  }

  /**
   * Extracts the HTTP request object from the GraphQL execution context.
   */
  private getGqlRequest(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req;
  }

  /**
   * Extracts a Bearer token from the Authorization header of an HTTP request.
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
