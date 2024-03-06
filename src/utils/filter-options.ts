import { I18nValidationError } from 'nestjs-i18n';

const reFormatErrors = (
  _: any,
  __: any,
  formattedErrors: Record<string, I18nValidationError>,
) => {
  const cleanErrors: Record<string, any>[] = [];

  for (const key in formattedErrors) {
    const constraints = formattedErrors[key].constraints ?? {};
    for (const error of Object.keys(constraints)) {
      const property = formattedErrors[key].property;
      const isKeyAlreadyExist = cleanErrors.findIndex(
        (value) => property in value,
      );
      if (isKeyAlreadyExist === -1) {
        cleanErrors.push({ [property]: constraints[error] });
      }
    }
  }

  return {
    errors: cleanErrors,
    status: 422,
    message: 'invalidInput',
  };
};

export const filterOptions = {
  detailedErrors: true,
  responseBodyFormatter: reFormatErrors,
};
