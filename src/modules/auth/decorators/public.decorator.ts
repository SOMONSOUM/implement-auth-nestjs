import { SetMetadata } from '@nestjs/common';

export const IS_PUBLICE_KEY = 'isPublic';

export const Public = (isPublic = true) =>
  SetMetadata(IS_PUBLICE_KEY, isPublic);