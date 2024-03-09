import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';
import { Transform } from 'class-transformer';
import { lowerCaseTransformer } from '../../utils/transformers/lower-case.transformer';
import { i18nValidationMessage } from 'nestjs-i18n';

export class AuthEmailLoginDto {
  @ApiProperty({ example: 'test1@example.com' })
  @Transform(lowerCaseTransformer)
  @IsEmail(
    {},
    {
      message: i18nValidationMessage('validation.isInvalid'),
    },
  )
  @IsNotEmpty({
    message: i18nValidationMessage('validation.isRequired'),
  })
  email: string;

  @ApiProperty()
  @IsNotEmpty({
    message: i18nValidationMessage('validation.isRequired'),
  })
  password: string;
}
