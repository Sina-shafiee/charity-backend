import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class AuthConfirmEmailDto {
  @ApiProperty()
  @IsNotEmpty()
  token: number;

  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
