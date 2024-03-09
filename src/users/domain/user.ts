import { Exclude, Expose } from 'class-transformer';
import { FileType } from 'src/files/domain/file';
import { Role } from 'src/roles/domain/role';
import { Status } from 'src/statuses/domain/status';

export class User {
  id: number | string;
  firstName: string | null;
  lastName: string | null;
  photo?: FileType | null;
  role?: Role | null;
  createdAt: Date;
  updatedAt: Date;

  @Exclude()
  password?: string;

  @Exclude()
  previousPassword?: string;

  @Expose({ groups: ['me', 'admin'] })
  email: string | null;

  @Expose({ groups: ['admin'] })
  provider: string;

  @Expose({ groups: ['admin'] })
  socialId?: string | null;

  @Expose({ groups: ['admin'] })
  status?: Status;

  @Expose({ groups: ['admin'] })
  emailVerified: Date | null;

  @Expose({ groups: ['admin'] })
  deletedAt: Date;
}
