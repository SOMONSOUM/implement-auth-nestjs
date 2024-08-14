import { ObjectType, PartialType } from '@nestjs/graphql';
import { LoginResponse } from './login.response';

@ObjectType()
export class RefreshTokenResponse extends PartialType(LoginResponse) {}
