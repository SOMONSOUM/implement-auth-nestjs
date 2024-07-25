import { Args, Mutation, Resolver, Query } from '@nestjs/graphql';
import { UserService } from './user.service';
import { CreateUserResponse } from './dto/response';
import { CreateUserInput } from './dto/input';
import { AllUsersResponse } from './dto/response/all-users.response';

@Resolver()
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  @Mutation(() => CreateUserResponse)
  async createUser(
    @Args('input') input: CreateUserInput,
  ): Promise<CreateUserResponse> {
    const createdUser = await this.userService.create(input);
    return {
      error: createdUser ? 0 : 1,
      message: createdUser ? 'OK' : 'Falied to create user',
      data: createdUser,
    };
  }

  @Query(() => AllUsersResponse)
  async getUser(): Promise<AllUsersResponse> {
    const users = await this.userService.findAll();
    return {
      error: users ? 0 : 1,
      message: users ? 'OK' : 'Failed to get users',
      data: users,
    };
  }
}
