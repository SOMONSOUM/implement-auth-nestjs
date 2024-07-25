import { Injectable, Logger, Param } from '@nestjs/common';
import { UserRepository } from './repositories/user.repository';
import { CreateUserInput } from './dto/input/create-user.input';
import { GraphQLError } from 'graphql';
import * as bcrypt from 'bcrypt';
import { saltOrRounds } from 'src/common/constants';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);
  constructor(private readonly userRepository: UserRepository) {}

  async findOneByEmail(@Param('email') email: string) {
    try {
      const user = await this.userRepository.findOne({ where: { email } });

      if (!user) {
        throw new GraphQLError(`User not found`, {
          extensions: {
            code: 'NOT_FOUND',
          },
        });
      }
      return user;
    } catch (error) {
      this.logger.error(error);
      if (error instanceof GraphQLError) {
        throw error;
      } else {
        throw new GraphQLError(`Something went wrong`, {
          extensions: {
            code: 'INTERNAL_SERVER_ERROR',
          },
        });
      }
    }
  }

  async findOneById(@Param('id') id: number) {
    try {
      const user = await this.userRepository.findOne({ where: { id } });

      if (!user) {
        throw new GraphQLError(`User not found`, {
          extensions: {
            code: 'NOT_FOUND',
          },
        });
      }
      return user;
    } catch (error) {
      this.logger.error(error);
      if (error instanceof GraphQLError) {
        throw error;
      } else {
        throw new GraphQLError(`Something went wrong`, {
          extensions: {
            code: 'INTERNAL_SERVER_ERROR',
          },
        });
      }
    }
  }

  async findAll() {
    try {
      const users = await this.userRepository.find();
      return users;
    } catch (error) {
      this.logger.error(error);
      if (error instanceof GraphQLError) {
        throw error;
      } else {
        throw new GraphQLError(`Something went wrong`, {
          extensions: {
            code: 'INTERNAL_SERVER_ERROR',
          },
        });
      }
    }
  }

  async create(input: CreateUserInput) {
    try {
      const user = await this.userRepository.findOne({
        where: { email: input.email },
      });

      if (user) {
        throw new GraphQLError(`Email already existed`, {
          extensions: {
            code: 'CONFLICT',
          },
        });
      }

      const hashedPassword = await bcrypt.hash(input.password, saltOrRounds);

      const savedUser = await this.userRepository.save({
        ...input,
        password: hashedPassword,
      });
      return savedUser;
    } catch (error) {
      this.logger.error(error);
      if (error instanceof GraphQLError) {
        throw error;
      } else {
        throw new GraphQLError(`Something went wrong`, {
          extensions: {
            code: 'INTERNAL_SERVER_ERROR',
          },
        });
      }
    }
  }
}
