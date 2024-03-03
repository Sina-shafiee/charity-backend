import { ApiProperty } from '@nestjs/swagger';
import { ResetPasswordToken } from '../domain/reset-password-token';
import { IsDate, IsEmail, IsNumber } from 'class-validator';

export class ResetPasswordTokenDto implements ResetPasswordToken {
  @ApiProperty()
  @IsNumber()
  id: number;

  @ApiProperty()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsNumber()
  token: number;

  @ApiProperty()
  @IsDate()
  expires: Date;
}
