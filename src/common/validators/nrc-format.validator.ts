import { registerDecorator, ValidationOptions } from 'class-validator';

export function IsValidNRC(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isValidNRC',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: any) {
          if (typeof value !== 'string') return false;

          // NRC patterns for English and Myanmar
          const pattern = {
            en: /^\d{1,2}\/[A-Z]{1,10}\((N|E|P|T|R|S)\)\d{5,6}$/,
            mm: /^[၀-၉]{1,2}\/[က-အ]{1,10}\((နိုင်|ဧည့်|ပြု|သာသနာ|ယာယီ|စ)\)([၀-၉]{5,6}|[0-9]{5,6})$/,
          };

          // Check if value matches either English or Myanmar NRC format
          return pattern.en.test(value) || pattern.mm.test(value);
        },

        defaultMessage() {
          return (
            'Invalid NRC format. ' +
            'Expected English format: 12/ABCDEF(N)123456 or ' +
            'Myanmar format: ၁၂/ကကက(နိုင်)၁၂၃၄၅၆'
          );
        },
      },
    });
  };
}
