import { Field, Int, ObjectType } from '@nestjs/graphql';
import { UserResponse } from './user.response';

@ObjectType()
export class CreateUserResponse {
  @Field(() => Int, { nullable: false })
  error: number;

  @Field(() => String, { nullable: false })
  message: string;

  @Field(() => UserResponse, { nullable: true })
  data: UserResponse;
}
