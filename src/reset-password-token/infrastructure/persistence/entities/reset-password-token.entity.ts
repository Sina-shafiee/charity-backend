import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { EntityRelationalHelper } from 'src/utils/relational-entity-helper';
import { ResetPasswordToken } from 'src/reset-password-token/domain/reset-password-token';

@Entity({
  name: 'resetPasswordToken',
})
export class ResetPasswordTokenEntity
  extends EntityRelationalHelper
  implements ResetPasswordToken
{
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column({ unique: true, type: 'int' })
  token: number;

  @Column()
  expires: Date;
}
