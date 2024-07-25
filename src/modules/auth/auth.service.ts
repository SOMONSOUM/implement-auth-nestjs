import { Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { LoginInput } from './dto/input/login.input';
import * as bcrypt from 'bcrypt';
import { GraphQLError } from 'graphql';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

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
    const accessToken = await this.jwtService.signAsync(payload);

    return accessToken;
  }
}
