export const verifyJWT = (
  jwtLifetime: number | undefined,
  expirationDate: number
): boolean => {
  if (jwtLifetime) {
    const currentDate = Math.floor(Date.now() / 1000);
    return expirationDate > currentDate;
  }
  return true;
};
