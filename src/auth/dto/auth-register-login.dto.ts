import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { lowerCaseTransformer } from '../../utils/transformers/lower-case.transformer';
import { i18nValidationMessage } from 'nestjs-i18n';

export class AuthRegisterLoginDto {
  @ApiProperty({ example: 'admin@example.com' })
  @Transform(lowerCaseTransformer)
  @IsEmail(
    {
      domain_specific_validation: true,
      host_whitelist: ['gmail.com', 'yahoo.com', 'hotmail.com'],
    },
    {
      message: i18nValidationMessage('validation.isInvalid'),
    },
  )
  email: string;

  @ApiProperty({ example: 'secret' })
  @MinLength(6, {
    message: i18nValidationMessage('validation.minLength'),
  })
  password: string;

  @ApiProperty({ example: 'John' })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.isRequired'),
  })
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.isRequired'),
  })
  lastName: string;
}
