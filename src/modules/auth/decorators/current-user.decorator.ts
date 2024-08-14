import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { UserEntity } from 'src/modules/user/entities/user.entity';

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): UserEntity => {
    if (context.getType() === 'http') {
      return context.switchToHttp().getRequest().user;
    }
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req.user;
  },
);
