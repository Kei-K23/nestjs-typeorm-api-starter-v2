import { IsString } from 'class-validator';

export class CreatePrivacyPolicyDto {
  @IsString({ message: 'Privacy policy must be a string' })
  privacyPolicy: string;
}
