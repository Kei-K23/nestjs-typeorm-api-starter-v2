import { IsString } from 'class-validator';

export class CreateTermAndConditionDto {
  @IsString({ message: 'Term and condition must be a string' })
  termAndCondition: string;
}
