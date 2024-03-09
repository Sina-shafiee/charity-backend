import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsNumber } from 'class-validator';
import { i18nValidationMessage } from 'nestjs-i18n';
import { I18nTranslations } from 'src/generated/i18n.generated';

export class AuthConfirmEmailDto {
  @ApiProperty()
  @IsNotEmpty({
    message: i18nValidationMessage<I18nTranslations>('validation.isRequired'),
  })
  @IsNumber(
    {},
    {
      message: i18nValidationMessage<I18nTranslations>('validation.isNumber'),
    },
  )
  token: number;

  @ApiProperty()
  @IsNotEmpty({
    message: i18nValidationMessage<I18nTranslations>('validation.isRequired'),
  })
  @IsEmail(
    {},
    {
      message: i18nValidationMessage<I18nTranslations>('validation.isInvalid'),
    },
  )
  email: string;
}
