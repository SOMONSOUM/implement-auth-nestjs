import { Field, Int, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class UserResponse {
  @Field(() => Int, { nullable: false })
  id: number;

  @Field(() => String, { nullable: false })
  email: string;

  @Field(() => Date)
  created_at: Date;

  @Field(() => Date)
  updated_at: Date;
}
