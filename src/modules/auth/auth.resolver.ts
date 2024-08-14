import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { LoginResponse } from './dto/response/login.response';
import { LoginInput } from './dto/input/login.input';
import { CurrentUser, Public } from './decorators';
import { UserResponse } from '../user/dto/response/user.response';
import { RefreshTokenResponse } from './dto/response/refresh-token.response';
import { RefreshTokenInput } from './dto/input/refresh-token.input';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Mutation(() => LoginResponse)
  async login(@Args('input') input: LoginInput): Promise<LoginResponse> {
    const { accessToken, refreshToken } = await this.authService.login(input);

    return {
      error: accessToken ? 0 : 1,
      message: accessToken ? 'OK' : 'Failed to login',
      accessToken,
      refreshToken,
    };
  }

  @Public()
  @Mutation(() => RefreshTokenResponse)
  async refreshToken(
    @Args('input') input: RefreshTokenInput,
  ): Promise<RefreshTokenResponse> {
    const { accessToken, refreshToken } =
      await this.authService.refreshToken(input);

    return {
      error: accessToken ? 0 : 1,
      message: accessToken ? 'OK' : 'Failed to login',
      accessToken,
      refreshToken,
    };
  }

  @Query(() => UserResponse)
  async getMe(@CurrentUser() user: UserResponse): Promise<UserResponse> {
    return user;
  }
}
