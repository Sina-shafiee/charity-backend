import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsNumber } from 'class-validator';
import { i18nValidationMessage } from 'nestjs-i18n';

export class AuthConfirmEmailDto {
  @ApiProperty()
  @IsNotEmpty({
    message: i18nValidationMessage('validation.isRequired'),
  })
  @IsNumber(
    {},
    {
      message: i18nValidationMessage('validation.isNumber'),
    },
  )
  token: number;

  @ApiProperty()
  @IsNotEmpty({
    message: i18nValidationMessage('validation.isRequired'),
  })
  @IsEmail(
    {},
    {
      message: i18nValidationMessage('validation.isInvalid'),
    },
  )
  email: string;
}
