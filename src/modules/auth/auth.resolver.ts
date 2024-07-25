import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { LoginResponse } from './dto/response/login.response';
import { LoginInput } from './dto/input/login.input';
import { CurrentUser, Public } from './decorators';
import { UserResponse } from '../user/dto/response/user.response';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Mutation(() => LoginResponse)
  async login(@Args('input') input: LoginInput): Promise<LoginResponse> {
    const accessToken = await this.authService.login(input);

    return {
      error: accessToken ? 0 : 1,
      message: accessToken ? 'OK' : 'Failed to login',
      accessToken,
    };
  }

  @Query(() => UserResponse)
  async getMe(@CurrentUser() user: UserResponse): Promise<UserResponse> {
    return user;
  }
}
