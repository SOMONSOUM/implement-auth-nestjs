import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as vault from 'node-vault';

@Injectable()
export class VaultService {
  vaultClient: vault.client;

  constructor(private readonly configService: ConfigService) {
    this.vaultClient = vault({
      apiVersion: 'v1',
      endpoint: this.configService.getOrThrow<string>('VAULT_ENDPOINT'),
      token: this.configService.getOrThrow<string>('VAULT_TOKEN'),
    });
  }

  async getSecret(path: string): Promise<Record<string, any>> {
    try {
      const secret = await this.vaultClient.read(path);
      console.log({ secret });

      return secret.data;
    } catch (error) {
      console.error(`Error reading secret from Vault: ${error.message}`);
      throw new Error('Could not fetch secret from Vault');
    }
  }
}
