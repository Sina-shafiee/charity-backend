import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import ms from 'ms';
import { JwtService } from '@nestjs/jwt';
import bcrypt from 'bcryptjs';
import { AuthEmailLoginDto } from './dto/auth-email-login.dto';
import { AuthUpdateDto } from './dto/auth-update.dto';
import { RoleEnum } from 'src/roles/roles.enum';
import { StatusEnum } from 'src/statuses/statuses.enum';
import { AuthProvidersEnum } from './auth-providers.enum';
import { SocialInterface } from '../social/interfaces/social.interface';
import { AuthRegisterLoginDto } from './dto/auth-register-login.dto';
import { MailService } from 'src/mail/mail.service';
import { NullableType } from '../utils/types/nullable.type';
import { LoginResponseType } from './types/login-response.type';
import { ConfigService } from '@nestjs/config';
import { AllConfigType } from 'src/config/config.type';
import { JwtPayloadType } from './strategies/types/jwt-payload.type';
import { User } from 'src/users/domain/user';
import { Session } from 'src/session/domain/session';
import { UsersService } from 'src/users/users.service';
import { SessionService } from 'src/session/session.service';
import { randomInt } from 'crypto';
import { VerificationTokenService } from 'src/verification-token/verification-token.service';
import { ResetPasswordTokenService } from 'src/reset-password-token/reset-password-token.service';
import { I18nContext } from 'nestjs-i18n';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private usersService: UsersService,
    private sessionService: SessionService,
    private mailService: MailService,
    private configService: ConfigService<AllConfigType>,
    private verificationTokenService: VerificationTokenService,
    private resetPasswordTokenService: ResetPasswordTokenService,
  ) {}

  async validateLogin(loginDto: AuthEmailLoginDto): Promise<LoginResponseType> {
    const i18n = I18nContext.current();
    const user = await this.usersService.findOne({
      email: loginDto.email,
    });

    if (!user) {
      throw new HttpException(
        {
          status: HttpStatus.FORBIDDEN,
          errors: i18n?.t('validation.notValidPassword'),
        },
        HttpStatus.FORBIDDEN,
      );
    }

    if (user.provider !== AuthProvidersEnum.email) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: i18n?.t('validation.needLoginViaAnotherProvider'),
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    if (!user.password) {
      throw new HttpException(
        {
          status: HttpStatus.FORBIDDEN,
          errors: i18n?.t('validation.notValidPassword'),
        },
        HttpStatus.FORBIDDEN,
      );
    }

    const isValidPassword = await bcrypt.compare(
      loginDto.password,
      user.password,
    );

    if (!isValidPassword) {
      throw new HttpException(
        {
          status: HttpStatus.FORBIDDEN,
          errors: i18n?.t('validation.notValidPassword'),
        },
        HttpStatus.FORBIDDEN,
      );
    }

    if (!user.emailVerified) {
      const token = this.randomToken();

      const verificationTokenExpiresIn = this.configService.getOrThrow(
        'auth.verificationEmailExpires',
        { infer: true },
      );
      const verificationTokenExpires =
        Date.now() + ms(verificationTokenExpiresIn);
      const verificationToken = await this.verificationTokenService.create({
        email: user.email!,
        token,
        expires: new Date(verificationTokenExpires),
      });

      await this.mailService.userSignUp({
        to: user.email!,
        data: {
          token: verificationToken.token,
        },
      });

      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: 'emailVerificationTokenSent',
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const session = await this.sessionService.create({
      user,
    });

    const { token, tokenExpires } = await this.getTokensData({
      id: user.id,
      role: user.role,
      sessionId: session.id,
    });

    return {
      token,
      tokenExpires,
      user,
    };
  }

  async validateSocialLogin(
    authProvider: string,
    socialData: SocialInterface,
  ): Promise<LoginResponseType> {
    let user: NullableType<User> = null;
    const socialEmail = socialData.email?.toLowerCase();
    let userByEmail: NullableType<User> = null;

    if (socialEmail) {
      userByEmail = await this.usersService.findOne({
        email: socialEmail,
      });
    }

    if (socialData.id) {
      user = await this.usersService.findOne({
        socialId: socialData.id,
        provider: authProvider,
      });
    }

    if (user) {
      if (socialEmail && !userByEmail) {
        user.email = socialEmail;
      }
      await this.usersService.update(user.id, user);
    } else if (userByEmail) {
      user = userByEmail;
    } else if (socialData.id) {
      const role = {
        id: RoleEnum.user,
      };
      const status = {
        id: StatusEnum.active,
      };

      user = await this.usersService.create({
        email: socialEmail ?? null,
        firstName: socialData.firstName ?? null,
        lastName: socialData.lastName ?? null,
        socialId: socialData.id,
        provider: authProvider,
        role,
        status,
      });

      user = await this.usersService.findOne({
        id: user?.id,
      });
    }

    if (!user) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            user: 'userNotFound',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const session = await this.sessionService.create({
      user,
    });

    const { token: jwtToken, tokenExpires } = await this.getTokensData({
      id: user.id,
      role: user.role,
      sessionId: session.id,
    });

    return {
      token: jwtToken,
      tokenExpires,
      user,
    };
  }

  async register(dto: AuthRegisterLoginDto): Promise<void> {
    const user = await this.usersService.create({
      ...dto,
      email: dto.email,
      role: {
        id: RoleEnum.user,
      },
      status: {
        id: StatusEnum.active,
      },
    });

    const token = this.randomToken();

    const verificationTokenExpiresIn = this.configService.getOrThrow(
      'auth.verificationEmailExpires',
      { infer: true },
    );
    const verificationTokenExpires =
      Date.now() + ms(verificationTokenExpiresIn);
    const verificationToken = await this.verificationTokenService.create({
      email: user.email!,
      token,
      expires: new Date(verificationTokenExpires),
    });

    await this.mailService.userSignUp({
      to: dto.email,
      data: {
        token: verificationToken.token,
      },
    });
  }

  async confirmEmail(passedToken: number, email: string): Promise<void> {
    const i18n = I18nContext.current();
    const user = await this.usersService.findOne({
      email,
    });

    if (!user || user.emailVerified || !user.email) {
      throw new HttpException(
        {
          status: HttpStatus.NOT_FOUND,
          errors: i18n?.t('validation.notFound', {
            args: { entityName: 'account' },
          }),
        },
        HttpStatus.NOT_FOUND,
      );
    }
    const userToken = await this.verificationTokenService.findOne({
      email: user.email,
    });

    if (!userToken) {
      throw new HttpException(
        {
          status: HttpStatus.NOT_FOUND,
          error: `notFound`,
        },
        HttpStatus.NOT_FOUND,
      );
    }
    if (userToken.token !== passedToken) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: i18n?.t('validation.invalidToken'),
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
    if (userToken.expires < new Date()) {
      throw new HttpException(
        {
          status: HttpStatus.CONFLICT,
          errors: i18n?.t('validation.expiredToken'),
        },
        HttpStatus.CONFLICT,
      );
    }

    user.emailVerified = new Date();

    await Promise.all([
      this.usersService.update(user.id, user),
      this.verificationTokenService.delete(user.email),
    ]);
  }

  async forgotPassword(email: string): Promise<void> {
    const user = await this.usersService.findOne({
      email,
    });

    if (!user || user.provider !== AuthProvidersEnum.email) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            email: 'emailNotExists',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const tokenExpiresIn = '1d';

    const tokenExpires = Date.now() + ms(tokenExpiresIn);

    const token = this.randomToken();

    const resetToken = await this.resetPasswordTokenService.create({
      email: user.email!,
      expires: new Date(tokenExpires),
      token,
    });

    await this.mailService.forgotPassword({
      to: email,
      data: {
        token: resetToken.token,
        tokenExpires,
      },
    });
  }

  async resetPassword(passedToken: number, password: string): Promise<void> {
    const resetPasswordToken = await this.resetPasswordTokenService.findOne({
      token: passedToken,
    });

    if (!resetPasswordToken || resetPasswordToken.token !== passedToken) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            hash: `notFound`,
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const user = await this.usersService.findOne({
      email: resetPasswordToken.email,
    });

    if (
      !user ||
      !user.emailVerified ||
      user.provider !== AuthProvidersEnum.email
    ) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            hash: `notFound`,
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    user.password = password;

    await this.sessionService.softDelete({
      user: {
        id: user.id,
      },
    });

    await this.usersService.update(user.id, user);
  }

  async me(userJwtPayload: JwtPayloadType): Promise<NullableType<User>> {
    return this.usersService.findOne({
      id: userJwtPayload.id,
    });
  }

  async update(
    userJwtPayload: JwtPayloadType,
    userDto: AuthUpdateDto,
  ): Promise<NullableType<User>> {
    if (userDto.password) {
      if (!userDto.oldPassword) {
        throw new HttpException(
          {
            status: HttpStatus.UNPROCESSABLE_ENTITY,
            errors: {
              oldPassword: 'missingOldPassword',
            },
          },
          HttpStatus.UNPROCESSABLE_ENTITY,
        );
      }

      const currentUser = await this.usersService.findOne({
        id: userJwtPayload.id,
      });

      if (!currentUser) {
        throw new HttpException(
          {
            status: HttpStatus.UNPROCESSABLE_ENTITY,
            errors: {
              user: 'userNotFound',
            },
          },
          HttpStatus.UNPROCESSABLE_ENTITY,
        );
      }

      if (!currentUser.password) {
        throw new HttpException(
          {
            status: HttpStatus.UNPROCESSABLE_ENTITY,
            errors: {
              oldPassword: 'incorrectOldPassword',
            },
          },
          HttpStatus.UNPROCESSABLE_ENTITY,
        );
      }

      const isValidOldPassword = await bcrypt.compare(
        userDto.oldPassword,
        currentUser.password,
      );

      if (!isValidOldPassword) {
        throw new HttpException(
          {
            status: HttpStatus.UNPROCESSABLE_ENTITY,
            errors: {
              oldPassword: 'incorrectOldPassword',
            },
          },
          HttpStatus.UNPROCESSABLE_ENTITY,
        );
      } else {
        await this.sessionService.softDelete({
          user: {
            id: currentUser.id,
          },
          excludeId: userJwtPayload.sessionId,
        });
      }
    }

    await this.usersService.update(userJwtPayload.id, userDto);

    return this.usersService.findOne({
      id: userJwtPayload.id,
    });
  }

  async softDelete(user: User): Promise<void> {
    await this.usersService.softDelete(user.id);
  }

  async logout(data: Pick<JwtPayloadType, 'sessionId'>) {
    return this.sessionService.softDelete({
      id: data.sessionId,
    });
  }

  private async getTokensData(data: {
    id: User['id'];
    role: User['role'];
    sessionId: Session['id'];
  }) {
    const tokenExpiresIn = this.configService.getOrThrow('auth.expires', {
      infer: true,
    });

    const tokenExpires = Date.now() + ms(tokenExpiresIn);

    const token = await this.jwtService.signAsync(
      {
        id: data.id,
        role: data.role,
        sessionId: data.sessionId,
      },
      {
        secret: this.configService.getOrThrow('auth.secret', { infer: true }),
        expiresIn: tokenExpiresIn,
      },
    );

    return {
      token,
      tokenExpires,
    };
  }
  randomToken() {
    const token = Math.floor(randomInt(100000, 999999));
    return token;
  }
}
