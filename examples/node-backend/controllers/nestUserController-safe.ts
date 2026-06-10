import { Controller, Get, Query, BadRequestException } from '@nestjs/common';
import { DataSource } from 'typeorm';
import axios from 'axios';

@Controller('nest-user')
export class NestUserControllerSafe {
  constructor(private dataSource: DataSource) {}

  @Get('profile')
  async getProfile(@Query('id') id: string) {
    // Safe: using parameterized raw query
    return this.dataSource.query('SELECT * FROM users WHERE id = $1', [id]);
  }

  @Get('proxy')
  async proxyRequest(@Query('url') url: string) {
    // Safe: validating target URL domain (SSRF mitigation)
    if (!url.startsWith('https://api.trusted.com/')) {
      throw new BadRequestException('Invalid target domain');
    }
    const response = await axios.get(url);
    return response.data;
  }
}
