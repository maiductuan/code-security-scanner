import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { DataSource } from 'typeorm';
import axios from 'axios';

@Controller('nest-user')
export class NestUserController {
  constructor(private dataSource: DataSource) {}

  @Get('profile')
  async getProfile(@Query('id') id: string, @Res() res: Response) {
    // SQL Injection in TypeORM raw query
    const users = await this.dataSource.query(`SELECT * FROM users WHERE id = ${id}`);
    res.send(users);
  }

  @Get('proxy')
  async proxyRequest(@Query('url') url: string) {
    // SSRF in axios call with unsanitized user URL
    const response = await axios.get(url);
    return response.data;
  }
}
