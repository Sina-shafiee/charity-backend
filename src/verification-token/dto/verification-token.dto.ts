import { ApiProperty } from '@nestjs/swagger';
import { VerificationToken } from '../domain/verification-token';
import { IsDate, IsEmail, IsNumber } from 'class-validator';

export class VerificationTokenDto implements VerificationToken {
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
