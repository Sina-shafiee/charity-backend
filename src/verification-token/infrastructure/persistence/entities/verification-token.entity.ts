import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { EntityRelationalHelper } from 'src/utils/relational-entity-helper';
import { VerificationToken } from 'src/verification-token/domain/verification-token';

@Entity({
  name: 'emailVerificationToken',
})
export class VerificationTokenEntity
  extends EntityRelationalHelper
  implements VerificationToken
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
