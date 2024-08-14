import { Field, Int, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class LoginResponse {
  @Field(() => Int, { nullable: false })
  error: number;

  @Field(() => String, { nullable: false })
  message: string;

  @Field(() => String, { nullable: true })
  accessToken: string;

  @Field(() => String, { nullable: true })
  refreshToken: string;
}
